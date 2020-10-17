table! {
    secrets (id) {
        id -> Int4,
        client_id -> Int4,
        name -> Varchar,
        content -> Varchar,
        url -> Nullable<Varchar>,
    }
}
