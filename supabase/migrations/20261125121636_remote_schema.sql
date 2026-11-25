SET local check_function_bodies = off;

SELECT cron.unschedule('mark-stale-devices-offline');

ALTER TABLE "public"."detection_logs"
  ADD COLUMN "event_id" uuid;

CREATE OR REPLACE FUNCTION public.admin_manage_device (
  p_admin_id  uuid,
  p_operation text,
  p_device_id uuid,
  p_payload   jsonb DEFAULT '{}'::jsonb
)
  RETURNS jsonb
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path TO ''
  AS $function$
DECLARE
  v_device       public.devices;
  v_name         text;
  v_location     text;
  v_ip           text;
  v_status       text;
  v_port         integer;
  v_port_bigint  bigint;

  v_admin_id CONSTANT uuid :=
    '8c24d05b-35a4-420d-b605-3b601ea6b229';

  v_protected_device_id CONSTANT uuid :=
    '3c4e8cb6-8d71-4e8f-b00d-4cf833949d3d';

BEGIN

  -- Verify administrator
  IF p_admin_id IS DISTINCT FROM v_admin_id THEN
    RETURN pg_catalog.jsonb_build_object(
      'success', false,
      'error', 'Unauthorized administrator.'
    );
  END IF;

  -- Validate operation
  IF p_operation NOT IN ('edit', 'archive') THEN
    RETURN pg_catalog.jsonb_build_object(
      'success', false,
      'error', 'Invalid operation.'
    );
  END IF;

  -- Lock device during operation
  SELECT *
  INTO v_device
  FROM public.devices
  WHERE id = p_device_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object(
      'success', false,
      'error', 'Device not found.'
    );
  END IF;

  -- EDIT DEVICE
  IF p_operation = 'edit' THEN

    v_name := NULLIF(
      BTRIM(p_payload->>'name'), ''
    );

    v_location := NULLIF(
      BTRIM(p_payload->>'location'), ''
    );

    IF v_name IS NULL THEN
      RETURN pg_catalog.jsonb_build_object(
        'success', false,
        'error', 'Device name is required.'
      );
    END IF;

    IF v_location IS NULL THEN
      RETURN pg_catalog.jsonb_build_object(
        'success', false,
        'error', 'Device location is required.'
      );
    END IF;

    -- Validate port
    IF COALESCE(p_payload->>'port', '') !~ '^[0-9]+$' THEN
      RETURN pg_catalog.jsonb_build_object(
        'success', false,
        'error', 'Invalid device port.'
      );
    END IF;

    v_port_bigint := (p_payload->>'port')::bigint;

    IF v_port_bigint NOT BETWEEN 1 AND 65535 THEN
      RETURN pg_catalog.jsonb_build_object(
        'success', false,
        'error', 'Port must be between 1 and 65535.'
      );
    END IF;

    v_port := v_port_bigint::integer;

    -- Validate status
    v_status := p_payload->>'status';

    IF v_status NOT IN ('online', 'offline') THEN
      RETURN pg_catalog.jsonb_build_object(
        'success', false,
        'error', 'Invalid device status.'
      );
    END IF;

    -- Handle IP address
    IF p_payload ? 'ip_address' THEN
      v_ip := NULLIF(
        BTRIM(p_payload->>'ip_address'), ''
      );
    ELSE
      v_ip := v_device.ip_address;
    END IF;

    -- Update device
    UPDATE public.devices
    SET
      name = v_name,
      location = v_location,
      ip_address = v_ip,
      port = v_port,
      status = v_status
    WHERE id = p_device_id
    RETURNING * INTO v_device;

  -- ARCHIVE DEVICE
  ELSIF p_operation = 'archive' THEN

    -- Protect primary device
    IF p_device_id = v_protected_device_id THEN
      RETURN pg_catalog.jsonb_build_object(
        'success', false,
        'error', 'The primary device cannot be archived.'
      );
    END IF;

    -- Prevent duplicate archiving
    IF v_device.is_archived THEN
      RETURN pg_catalog.jsonb_build_object(
        'success', false,
        'error', 'Device is already archived.'
      );
    END IF;

    UPDATE public.devices
    SET
      is_archived = true,
      archived_at = pg_catalog.now(),
      archived_by = p_admin_id
    WHERE id = p_device_id
    RETURNING * INTO v_device;

  END IF;

  -- Return updated device
  RETURN pg_catalog.jsonb_build_object(
    'success', true,
    'device', pg_catalog.to_jsonb(v_device)
  );

EXCEPTION
  WHEN OTHERS THEN
    RETURN pg_catalog.jsonb_build_object(
      'success', false,
      'error', SQLERRM
    );

END;
$function$;

CREATE OR REPLACE FUNCTION public.assign_device_to_farmer (
  p_device_id uuid,
  p_user_id   uuid
)
  RETURNS uuid
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path TO ''
  AS $function$
DECLARE
    v_assignment_id uuid;
    v_is_archived boolean;
BEGIN
    -- Only authenticated administrators can assign devices.
    IF auth.uid() IS NULL
       OR NOT public.is_scarecrow_admin() THEN
        RAISE EXCEPTION 'Only administrators can assign devices.';
    END IF;

    -- Lock the device row and check whether it exists.
    SELECT d.is_archived
    INTO v_is_archived
    FROM public.devices AS d
    WHERE d.id = p_device_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Device does not exist.';
    END IF;

    IF COALESCE(v_is_archived, false) THEN
        RAISE EXCEPTION 'Archived devices cannot be assigned.';
    END IF;

    -- End the previous active assignment.
    UPDATE public.device_assignments
    SET unassigned_at = now()
    WHERE device_id = p_device_id
      AND unassigned_at IS NULL;

    -- Create the new assignment.
    INSERT INTO public.device_assignments (
        device_id,
        user_id,
        assigned_by
    )
    VALUES (
        p_device_id,
        p_user_id,
        auth.uid()
    )
    RETURNING id INTO v_assignment_id;

    RETURN v_assignment_id;
END;
$function$;

CREATE OR REPLACE FUNCTION public.get_admin_clients()
  RETURNS SETOF public.profiles
  LANGUAGE plpgsql
  STABLE
  SECURITY DEFINER
  SET search_path TO ''
  AS $function$
BEGIN
    IF NOT public.is_scarecrow_admin() THEN
        RAISE EXCEPTION 'Not authorized';
    END IF;

    RETURN QUERY
    SELECT p.*
    FROM public.profiles AS p
    WHERE NOT EXISTS (
        SELECT 1
        FROM public.admin_users AS a
        WHERE a.user_id = p.id
    )
    ORDER BY p.created_at DESC;
END;
$function$;

CREATE OR REPLACE FUNCTION public.is_scarecrow_admin()
  RETURNS boolean
  LANGUAGE sql
  STABLE
  SECURITY DEFINER
  SET search_path TO ''
  AS $function$
  SELECT EXISTS (
    SELECT 1
    FROM public.admin_users
    WHERE user_id = (SELECT auth.uid())
  );
$function$;

CREATE OR REPLACE FUNCTION public.log_device_status_change()
  RETURNS TRIGGER
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path TO 'public'
  AS $function$
BEGIN
  IF NEW.status IS DISTINCT FROM OLD.status
     AND NEW.status IN ('online', 'offline') THEN

    INSERT INTO public.detection_logs
      (device_id, event_type, label)
    VALUES (
      NEW.id,
      NEW.status,
      CASE
        WHEN NEW.status = 'online'
          THEN 'Device came back online'
        ELSE
          'Device stopped sending heartbeat'
      END
    );

  END IF;

  RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION public.prevent_archived_device_assignment()
  RETURNS TRIGGER
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path TO 'public'
  AS $function$
DECLARE
    device_is_archived boolean;
BEGIN
    IF NEW.unassigned_at IS NULL THEN

        SELECT is_archived
        INTO device_is_archived
        FROM public.devices
        WHERE id = NEW.device_id;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'Device does not exist.';
        END IF;

        IF COALESCE(device_is_archived, false) THEN
            RAISE EXCEPTION 'Archived devices cannot be assigned.';
        END IF;

    END IF;

    RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION public.update_updated_at_column()
  RETURNS TRIGGER
  LANGUAGE plpgsql
  AS $function$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$function$;

CREATE UNIQUE INDEX detection_logs_event_id_unique ON public.detection_logs USING btree (event_id);

SELECT cron.schedule_in_database('mark-stale-devices-offline', '30 seconds', '
    update public.devices
    set status = ''offline''
    where status = ''online''
      and (last_seen is null or last_seen < now() - interval ''30 seconds'');
  ', 'postgres', NULL, true);

