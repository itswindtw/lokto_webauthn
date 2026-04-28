(* System *)
let uuid = Uuidm.v4_gen (Random.State.make_self_init ())
let user_store = Hashtbl.create 10
let credential_store = Hashtbl.create 10

(* Shared *)
let allow_cross_origin = false
let require_user_verification = false

let check_origin ~rp_id origin =
  match Uri.of_string origin |> Uri.host with
  | Some host -> host = rp_id
  | _ -> false

let fetch_credential_record ~user_handle ~credential_id =
  let open Result.Syntax in
  (* lookup credential_id from user_store with user_handle (user_id) *)
  let* user_id =
    Option.to_result ~none:"User handle is not present" user_handle
  in
  let user_credential_ids = Hashtbl.find_all user_store user_id in

  (* credential_id should be in the list *)
  let* () =
    if List.mem credential_id user_credential_ids then Ok ()
    else Error "credential_id is not in user_credential_ids"
  in

  (* fetch credential with credential_id *)
  Hashtbl.find_opt credential_store credential_id
  |> Option.to_result ~none:"Credential Not Found"

(* PRF *)
let salt =
  Lokto_webauthn.Spec.Base64_url_string.of_raw "Salt for new symmetric key"

let extensions =
  `Assoc
    [
      ( "prf",
        `Assoc
          [
            ( "eval",
              `Assoc
                [
                  ("first", Lokto_webauthn.Spec.Base64_url_string.to_json salt);
                ] );
          ] );
    ]

let () =
  let port = Sys.getenv_opt "PORT" |> Option.map int_of_string in
  let rp_id =
    Sys.getenv_opt "RENDER_EXTERNAL_HOSTNAME"
    |> Option.value ~default:"localhost"
  in
  let check_origin = check_origin ~rp_id in

  Dream.run ~interface:"0.0.0.0" ?port
  @@ Dream.logger @@ Dream.memory_sessions
  @@ Dream.router
       [
         Dream.get "/" (fun _ ->
             Dream.html (Assets.read "/index.html" |> Option.get));
         Dream.post "/registration/options/:username" (fun request ->
             let user_name = Dream.param request "username" in

             let user_id = uuid () |> Uuidm.to_binary_string in
             let authenticator_selection =
               Lokto_webauthn.Spec.Authenticator_selection_criteria.
                 {
                   resident_key = Some Required;
                   authenticator_attachment = None;
                   user_verification = Some Preferred;
                 }
             in
             let options =
               Lokto_webauthn.Registration.Options.make ~rp_id ~user_id
                 ~user_name ~authenticator_selection ~extensions ()
             in

             let%lwt () =
               Dream.set_session_field request "challenge"
                 (Lokto_webauthn.Spec.Base64_url_string.to_raw options.challenge)
             in
             let%lwt () = Dream.set_session_field request "user_id" user_id in

             Dream.json
               (options |> Lokto_webauthn.Registration.Options.to_json
              |> Lokto_webauthn.Json.to_string));
         Dream.post "/registration" (fun request ->
             match
               ( Dream.session_field request "user_id",
                 Dream.session_field request "challenge" )
             with
             | None, _ | _, None -> Dream.empty `Bad_Request
             | Some user_id, Some challenge -> (
                 let%lwt registration_response = Dream.body request in
                 let challenge =
                   Lokto_webauthn.Spec.Base64_url_string.of_raw challenge
                 in

                 match
                   Lokto_webauthn.Registration.Response.verify
                     ~registration_response ~challenge ~rp_id ~check_origin
                     ~check_attestation:(fun ~attestation_type ~trust_path ->
                       true)
                     ~allow_cross_origin ~require_user_present:true
                     ~require_user_verification
                     ~is_credential_id_registered:(fun credential_id ->
                       Hashtbl.mem credential_store credential_id)
                     ()
                 with
                 | Ok { credential_record } ->
                     Hashtbl.add user_store user_id credential_record.id;
                     Hashtbl.replace credential_store credential_record.id
                       credential_record;

                     Dream.json
                       (`Assoc
                          [
                            ( "credential_id",
                              `String
                                Lokto_webauthn.Spec.Base64_url_string.(
                                  credential_record.id |> of_raw |> to_encoded)
                            );
                            ( "user_id",
                              `String
                                Lokto_webauthn.Spec.Base64_url_string.(
                                  user_id |> of_raw |> to_encoded) );
                          ]
                       |> Yojson.to_string)
                 | Error msg -> Dream.html ~status:`Bad_Request msg));
         Dream.post "/authentication/options" (fun request ->
             let options =
               Lokto_webauthn.Authentication.Options.make ~rp_id
                 ~user_verification:Preferred ~allow_credentials:[] ~extensions
                 ()
             in

             let%lwt () =
               Dream.set_session_field request "challenge"
                 (options.challenge
                |> Lokto_webauthn.Spec.Base64_url_string.to_raw)
             in

             Dream.json
               (options |> Lokto_webauthn.Authentication.Options.to_json
              |> Lokto_webauthn.Json.to_string));
         Dream.post "/authentication" (fun request ->
             match Dream.session_field request "challenge" with
             | None -> Dream.empty `Bad_Request
             | Some challenge -> (
                 let%lwt authentication_response = Dream.body request in
                 let challenge =
                   Lokto_webauthn.Spec.Base64_url_string.of_raw challenge
                 in
                 match
                   Lokto_webauthn.Authentication.Response.verify
                     ~authentication_response ~challenge ~rp_id
                     ~fetch_credential_record ~check_origin ~allow_cross_origin
                     ~require_user_verification ()
                 with
                 | Ok { credential_record; user_handle } ->
                     Hashtbl.replace credential_store credential_record.id
                       credential_record;

                     Dream.json
                       (`Assoc
                          [
                            ( "credential_id",
                              `String
                                Lokto_webauthn.Spec.Base64_url_string.(
                                  credential_record.id |> of_raw |> to_encoded)
                            );
                            ( "user_id",
                              Option.fold ~none:`Null
                                ~some:(fun x ->
                                  `String
                                    Lokto_webauthn.Spec.Base64_url_string.(
                                      x |> of_raw |> to_encoded))
                                user_handle );
                          ]
                       |> Yojson.to_string)
                 | Error msg -> Dream.html ~status:`Bad_Request msg));
       ]
