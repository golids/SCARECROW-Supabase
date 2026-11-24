SET local check_function_bodies = off;

CREATE EXTENSION "pg_cron";

CREATE TABLE "public"."admin_users" (
  "user_id"    uuid                     NOT NULL,
  "created_at" timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT "admin_users_pkey" PRIMARY KEY (user_id)
);

ALTER TABLE "public"."admin_users"
  ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE "public"."admin_users" FROM "anon", "authenticated";

CREATE TABLE "public"."detection_logs" (
  "id"         bigint                   GENERATED ALWAYS AS IDENTITY NOT NULL,
  "device_id"  uuid                     NOT NULL,
  "event_type" text                     NOT NULL,
  "label"      text                     NOT NULL,
  "species"    text,
  "confidence" numeric,
  "image_url"  text,
  "created_at" timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT "detection_logs_pkey" PRIMARY KEY (id)
);

ALTER TABLE "public"."detection_logs"
  ENABLE ROW LEVEL SECURITY;

CREATE TABLE "public"."device_assignments" (
  "id"            uuid                     NOT NULL DEFAULT gen_random_uuid(),
  "device_id"     uuid                     NOT NULL,
  "user_id"       uuid                     NOT NULL,
  "assigned_at"   timestamp with time zone NOT NULL DEFAULT now(),
  "unassigned_at" timestamp with time zone,
  "assigned_by"   uuid,
  CONSTRAINT "device_assignments_pkey" PRIMARY KEY (id),
  CONSTRAINT "valid_assignment_dates" CHECK (((unassigned_at IS NULL) OR (unassigned_at >= assigned_at)))
);

ALTER TABLE "public"."device_assignments"
  ENABLE ROW LEVEL SECURITY;

CREATE TABLE "public"."device_audit_logs" (
  "id"         bigint                   GENERATED ALWAYS AS IDENTITY NOT NULL,
  "device_id"  uuid,
  "actor_id"   uuid,
  "action"     text                     NOT NULL,
  "details"    jsonb                    NOT NULL DEFAULT '{}'::jsonb,
  "created_at" timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT "device_audit_logs_pkey" PRIMARY KEY (id)
);

ALTER TABLE "public"."device_audit_logs"
  ENABLE ROW LEVEL SECURITY;

CREATE TABLE "public"."devices" (
  "id"          uuid                     NOT NULL DEFAULT gen_random_uuid(),
  "name"        text                     NOT NULL,
  "location"    text                     NOT NULL,
  "ip_address"  text,
  "port"        integer                  NOT NULL DEFAULT 5000,
  "status"      text                     NOT NULL DEFAULT 'offline'::text,
  "last_seen"   timestamp with time zone,
  "created_at"  timestamp with time zone NOT NULL DEFAULT now(),
  "is_locked"   boolean                  NOT NULL DEFAULT true,
  "is_archived" boolean                  NOT NULL DEFAULT false,
  "archived_at" timestamp with time zone,
  "archived_by" uuid,
  CONSTRAINT "devices_pkey" PRIMARY KEY (id),
  CONSTRAINT "devices_status_check" CHECK ((status = ANY (ARRAY['online'::text, 'offline'::text])))
);

ALTER TABLE "public"."devices"
  ENABLE ROW LEVEL SECURITY;

CREATE TABLE "public"."maintenance_notes" (
  "id"         uuid                     NOT NULL DEFAULT gen_random_uuid(),
  "device_id"  uuid                     NOT NULL,
  "note"       text                     NOT NULL,
  "created_by" uuid,
  "created_at" timestamp with time zone NOT NULL DEFAULT now(),
  "updated_at" timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT "maintenance_notes_note_check" CHECK ((length(TRIM(BOTH FROM note)) > 0)),
  CONSTRAINT "maintenance_notes_pkey" PRIMARY KEY (id)
);

ALTER TABLE "public"."maintenance_notes"
  ENABLE ROW LEVEL SECURITY;

CREATE TABLE "public"."notification_preferences" (
  "user_id"              uuid                     NOT NULL,
  "device_disconnection" boolean                  NOT NULL DEFAULT true,
  "device_errors"        boolean                  NOT NULL DEFAULT true,
  "low_battery"          boolean                  NOT NULL DEFAULT true,
  "device_recovery"      boolean                  NOT NULL DEFAULT true,
  "bird_detection"       boolean                  NOT NULL DEFAULT false,
  "updated_at"           timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT "notification_preferences_pkey" PRIMARY KEY (user_id)
);

ALTER TABLE "public"."notification_preferences"
  ENABLE ROW LEVEL SECURITY;

CREATE TABLE "public"."profiles" (
  "id"             uuid                     NOT NULL,
  "full_name"      text,
  "contact_number" text,
  "province"       text,
  "municipality"   text,
  "barangay"       text,
  "created_at"     timestamp with time zone NOT NULL DEFAULT timezone('utc'::text, now()),
  "updated_at"     timestamp with time zone NOT NULL DEFAULT timezone('utc'::text, now()),
  CONSTRAINT "profiles_pkey" PRIMARY KEY (id)
);

ALTER TABLE "public"."profiles"
  ENABLE ROW LEVEL SECURITY;

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

REVOKE ALL ON FUNCTION "public"."admin_manage_device"(uuid, text, uuid, jsonb) FROM PUBLIC, "anon", "authenticated";

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

ALTER TABLE "public"."admin_users"
  ADD CONSTRAINT "admin_users_user_id_fkey" FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;

ALTER TABLE "public"."device_assignments"
  ADD CONSTRAINT "device_assignments_assigned_by_fkey" FOREIGN KEY (assigned_by) REFERENCES auth.users(id);

ALTER TABLE "public"."device_audit_logs"
  ADD CONSTRAINT "device_audit_logs_actor_id_fkey" FOREIGN KEY (actor_id) REFERENCES auth.users(id) ON DELETE SET NULL;

ALTER TABLE "public"."devices"
  ADD CONSTRAINT "devices_archived_by_fkey" FOREIGN KEY (archived_by) REFERENCES auth.users(id) ON DELETE SET NULL;

ALTER TABLE "public"."detection_logs"
  ADD CONSTRAINT "detection_logs_device_id_fkey" FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE CASCADE;

ALTER TABLE "public"."device_assignments"
  ADD CONSTRAINT "device_assignments_device_id_fkey" FOREIGN KEY (device_id) REFERENCES public.devices(id);

ALTER TABLE "public"."device_audit_logs"
  ADD CONSTRAINT "device_audit_logs_device_id_fkey" FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE SET NULL;

ALTER TABLE "public"."maintenance_notes"
  ADD CONSTRAINT "maintenance_notes_created_by_fkey" FOREIGN KEY (created_by) REFERENCES auth.users(id) ON DELETE SET NULL;

ALTER TABLE "public"."maintenance_notes"
  ADD CONSTRAINT "maintenance_notes_device_id_fkey" FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE RESTRICT;

ALTER TABLE "public"."notification_preferences"
  ADD CONSTRAINT "notification_preferences_user_id_fkey" FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;

ALTER TABLE "public"."profiles"
  ADD CONSTRAINT "profiles_id_fkey" FOREIGN KEY (id) REFERENCES auth.users(id);

ALTER TABLE "public"."device_assignments"
  ADD CONSTRAINT "device_assignments_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public.profiles(id);

CREATE INDEX detection_logs_created_at_idx ON public.detection_logs USING btree (created_at DESC);

CREATE INDEX detection_logs_device_id_idx ON public.detection_logs USING btree (device_id);

CREATE INDEX idx_device_assignments_user_id ON public.device_assignments USING btree (user_id);

CREATE INDEX idx_device_audit_logs_created ON public.device_audit_logs USING btree (created_at DESC);

CREATE INDEX idx_device_audit_logs_device ON public.device_audit_logs USING btree (device_id);

CREATE INDEX idx_devices_active ON public.devices USING btree (is_archived, name);

CREATE INDEX idx_maintenance_notes_device ON public.maintenance_notes USING btree (device_id, created_at DESC);

CREATE UNIQUE INDEX one_active_farmer_per_device ON public.device_assignments USING btree (device_id)
  WHERE (unassigned_at IS NULL);

CREATE TRIGGER check_device_assignment_status
  BEFORE INSERT OR UPDATE OF device_id, unassigned_at ON public.device_assignments
  FOR EACH ROW
  EXECUTE FUNCTION public.prevent_archived_device_assignment();

CREATE TRIGGER devices_log_status_change
  AFTER UPDATE OF status ON public.devices
  FOR EACH ROW
  EXECUTE FUNCTION public.log_device_status_change();

CREATE TRIGGER update_profiles_updated_at
  BEFORE UPDATE ON public.profiles
  FOR EACH ROW
  EXECUTE FUNCTION public.update_updated_at_column();

CREATE POLICY "Admins and assigned clients can read detection logs" ON "public"."detection_logs"
  FOR SELECT
  TO "authenticated"
  USING ((public.is_scarecrow_admin() OR (EXISTS ( SELECT 1
   FROM public.device_assignments da
  WHERE ((da.device_id = detection_logs.device_id) AND (da.user_id = auth.uid()) AND (da.unassigned_at IS NULL))))));

CREATE POLICY "Admins and farmers can view assignments" ON "public"."device_assignments"
  FOR SELECT
  TO "authenticated"
  USING ((public.is_scarecrow_admin() OR (auth.uid() = user_id)));

CREATE POLICY "Admins can create assignments" ON "public"."device_assignments"
  FOR INSERT
  TO "authenticated"
  WITH CHECK ((public.is_scarecrow_admin() AND (assigned_by = auth.uid())));

CREATE POLICY "Admins can update assignments" ON "public"."device_assignments"
  FOR UPDATE
  TO "authenticated"
  USING (public.is_scarecrow_admin())
  WITH CHECK (public.is_scarecrow_admin());

CREATE POLICY "Admin can read device audit logs" ON "public"."device_audit_logs"
  FOR SELECT
  TO "authenticated"
  USING (public.is_scarecrow_admin());

CREATE POLICY "Admins and assigned clients can read devices" ON "public"."devices"
  FOR SELECT
  TO "authenticated"
  USING ((public.is_scarecrow_admin() OR ((is_archived = false) AND (EXISTS ( SELECT 1
   FROM public.device_assignments da
  WHERE ((da.device_id = devices.id) AND (da.user_id = auth.uid()) AND (da.unassigned_at IS NULL)))))));

CREATE POLICY "Admin can add maintenance notes" ON "public"."maintenance_notes"
  FOR INSERT
  TO "authenticated"
  WITH CHECK ((public.is_scarecrow_admin() AND (created_by = auth.uid())));

CREATE POLICY "Admin can read maintenance notes" ON "public"."maintenance_notes"
  FOR SELECT
  TO "authenticated"
  USING (public.is_scarecrow_admin());

CREATE POLICY "Admin can update maintenance notes" ON "public"."maintenance_notes"
  FOR UPDATE
  TO "authenticated"
  USING (public.is_scarecrow_admin())
  WITH CHECK (public.is_scarecrow_admin());

CREATE POLICY "Admin can insert notification preferences" ON "public"."notification_preferences"
  FOR INSERT
  TO "authenticated"
  WITH CHECK ((public.is_scarecrow_admin() AND (user_id = auth.uid())));

CREATE POLICY "Admin can read notification preferences" ON "public"."notification_preferences"
  FOR SELECT
  TO "authenticated"
  USING ((public.is_scarecrow_admin() AND (user_id = auth.uid())));

CREATE POLICY "Admin can update notification preferences" ON "public"."notification_preferences"
  FOR UPDATE
  TO "authenticated"
  USING ((public.is_scarecrow_admin() AND (user_id = auth.uid())))
  WITH CHECK ((public.is_scarecrow_admin() AND (user_id = auth.uid())));

CREATE POLICY "Admins can view all client profiles" ON "public"."profiles"
  FOR SELECT
  TO "authenticated"
  USING (public.is_scarecrow_admin());

CREATE POLICY "Users can insert their own profile" ON "public"."profiles"
  FOR INSERT
  TO PUBLIC
  WITH CHECK ((auth.uid() = id));

CREATE POLICY "Users can update their own profile" ON "public"."profiles"
  FOR UPDATE
  TO "authenticated"
  USING ((auth.uid() = id))
  WITH CHECK ((auth.uid() = id));

CREATE POLICY "Users can view their own profile" ON "public"."profiles"
  FOR SELECT
  TO PUBLIC
  USING ((auth.uid() = id));

ALTER PUBLICATION "supabase_realtime" ADD TABLE "public"."detection_logs";

COMMENT ON EXTENSION "pg_cron" IS 'Job scheduler for PostgreSQL';

REVOKE ALL ON FUNCTION "public"."admin_manage_device"(uuid, text, uuid, jsonb) FROM "postgres";

GRANT EXECUTE ON FUNCTION "public"."admin_manage_device"(uuid, text, uuid, jsonb) TO "postgres";

GRANT EXECUTE ON FUNCTION "public"."admin_manage_device"(uuid, text, uuid, jsonb) TO "service_role";

GRANT EXECUTE ON FUNCTION "public"."assign_device_to_farmer"(uuid, uuid) TO PUBLIC, "anon", "authenticated";

REVOKE ALL ON FUNCTION "public"."assign_device_to_farmer"(uuid, uuid) FROM "postgres";

GRANT EXECUTE ON FUNCTION "public"."assign_device_to_farmer"(uuid, uuid) TO "postgres";

GRANT EXECUTE ON FUNCTION "public"."assign_device_to_farmer"(uuid, uuid) TO "service_role";

REVOKE ALL ON FUNCTION "public"."get_admin_clients"() FROM PUBLIC;

GRANT EXECUTE ON FUNCTION "public"."get_admin_clients"() TO "anon", "authenticated";

REVOKE ALL ON FUNCTION "public"."get_admin_clients"() FROM "postgres";

GRANT EXECUTE ON FUNCTION "public"."get_admin_clients"() TO "postgres";

GRANT EXECUTE ON FUNCTION "public"."get_admin_clients"() TO "service_role";

REVOKE ALL ON FUNCTION "public"."is_scarecrow_admin"() FROM PUBLIC;

GRANT EXECUTE ON FUNCTION "public"."is_scarecrow_admin"() TO "anon", "authenticated";

REVOKE ALL ON FUNCTION "public"."is_scarecrow_admin"() FROM "postgres";

GRANT EXECUTE ON FUNCTION "public"."is_scarecrow_admin"() TO "postgres";

GRANT EXECUTE ON FUNCTION "public"."is_scarecrow_admin"() TO "service_role";

GRANT EXECUTE ON FUNCTION "public"."log_device_status_change"() TO PUBLIC, "anon", "authenticated";

REVOKE ALL ON FUNCTION "public"."log_device_status_change"() FROM "postgres";

GRANT EXECUTE ON FUNCTION "public"."log_device_status_change"() TO "postgres";

GRANT EXECUTE ON FUNCTION "public"."log_device_status_change"() TO "service_role";

GRANT EXECUTE ON FUNCTION "public"."prevent_archived_device_assignment"() TO PUBLIC, "anon", "authenticated";

REVOKE ALL ON FUNCTION "public"."prevent_archived_device_assignment"() FROM "postgres";

GRANT EXECUTE ON FUNCTION "public"."prevent_archived_device_assignment"() TO "postgres";

GRANT EXECUTE ON FUNCTION "public"."prevent_archived_device_assignment"() TO "service_role";

GRANT EXECUTE ON FUNCTION "public"."update_updated_at_column"() TO PUBLIC, "anon", "authenticated";

REVOKE ALL ON FUNCTION "public"."update_updated_at_column"() FROM "postgres";

GRANT EXECUTE ON FUNCTION "public"."update_updated_at_column"() TO "postgres";

GRANT EXECUTE ON FUNCTION "public"."update_updated_at_column"() TO "service_role";

REVOKE ALL ON SEQUENCE "public"."detection_logs_id_seq" FROM "anon";

GRANT SELECT, UPDATE, USAGE ON SEQUENCE "public"."detection_logs_id_seq" TO "anon";

REVOKE ALL ON SEQUENCE "public"."detection_logs_id_seq" FROM "authenticated";

GRANT SELECT, UPDATE, USAGE ON SEQUENCE "public"."detection_logs_id_seq" TO "authenticated";

REVOKE ALL ON SEQUENCE "public"."detection_logs_id_seq" FROM "postgres";

GRANT SELECT, UPDATE, USAGE ON SEQUENCE "public"."detection_logs_id_seq" TO "postgres";

REVOKE ALL ON SEQUENCE "public"."detection_logs_id_seq" FROM "service_role";

GRANT SELECT, UPDATE, USAGE ON SEQUENCE "public"."detection_logs_id_seq" TO "service_role";

REVOKE ALL ON SEQUENCE "public"."device_audit_logs_id_seq" FROM "anon";

GRANT SELECT, UPDATE, USAGE ON SEQUENCE "public"."device_audit_logs_id_seq" TO "anon";

REVOKE ALL ON SEQUENCE "public"."device_audit_logs_id_seq" FROM "authenticated";

GRANT SELECT, UPDATE, USAGE ON SEQUENCE "public"."device_audit_logs_id_seq" TO "authenticated";

REVOKE ALL ON SEQUENCE "public"."device_audit_logs_id_seq" FROM "postgres";

GRANT SELECT, UPDATE, USAGE ON SEQUENCE "public"."device_audit_logs_id_seq" TO "postgres";

REVOKE ALL ON SEQUENCE "public"."device_audit_logs_id_seq" FROM "service_role";

GRANT SELECT, UPDATE, USAGE ON SEQUENCE "public"."device_audit_logs_id_seq" TO "service_role";

REVOKE ALL ON TABLE "public"."admin_users" FROM "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."admin_users" TO "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."admin_users" TO "service_role";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."detection_logs" TO "anon", "authenticated";

REVOKE ALL ON TABLE "public"."detection_logs" FROM "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."detection_logs" TO "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."detection_logs" TO "service_role";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."device_assignments" TO "anon", "authenticated";

REVOKE ALL ON TABLE "public"."device_assignments" FROM "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."device_assignments" TO "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."device_assignments" TO "service_role";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."device_audit_logs" TO "anon", "authenticated";

REVOKE ALL ON TABLE "public"."device_audit_logs" FROM "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."device_audit_logs" TO "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."device_audit_logs" TO "service_role";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."devices" TO "anon", "authenticated";

REVOKE ALL ON TABLE "public"."devices" FROM "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."devices" TO "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."devices" TO "service_role";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."maintenance_notes" TO "anon", "authenticated";

REVOKE ALL ON TABLE "public"."maintenance_notes" FROM "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."maintenance_notes" TO "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."maintenance_notes" TO "service_role";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."notification_preferences" TO "anon", "authenticated";

REVOKE ALL ON TABLE "public"."notification_preferences" FROM "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."notification_preferences" TO "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."notification_preferences" TO "service_role";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."profiles" TO "anon", "authenticated";

REVOKE ALL ON TABLE "public"."profiles" FROM "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."profiles" TO "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."profiles" TO "service_role";

SELECT cron.schedule_in_database('mark-stale-devices-offline', '30 seconds', '
    update public.devices
    set status = ''offline''
    where status = ''online''
      and (last_seen is null or last_seen < now() - interval ''30 seconds'');
  ', 'postgres', NULL, true);

