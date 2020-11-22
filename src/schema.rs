table! {
    secrets (id) {
        id -> Int4,
        client_side_id -> Varchar,
        name -> Varchar,
        content -> Varchar,
        url -> Nullable<Varchar>,
    }
}

table! {
    user_secret (user_id, secret_id) {
        user_id -> Varchar,
        secret_id -> Int4,
        secret_id_client_side -> Varchar,
    }
}

joinable!(user_secret -> secrets (secret_id));

allow_tables_to_appear_in_same_query!(
    secrets,
    user_secret,
);
