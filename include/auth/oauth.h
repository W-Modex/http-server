#ifndef OAUTH_H
#define OAUTH_H

#include <bits/pthreadtypes.h>
#include <stdint.h>
#define STATE_LEN 65
#define NONCE_LEN 65
#define CODE_VERIFIER_LEN 97
#define FLOW_BUCKETS 256
#define OAUTH_FLOW_TTL_MS (10 * 60 * 1000)

typedef struct {
    const char *name; 
    const char *authorize_url;
    const char *token_url;    
    const char *jwks_url;     
    const char *issuer;        

    const char *client_id;
    const char *client_secret;

    const char *redirect_uri; 

    const char *scope; 

} oauth_provider_t;

typedef struct oauth_flow {
    char state[STATE_LEN];
    char nonce[NONCE_LEN];         
    char code_verifier[CODE_VERIFIER_LEN]; 

    const oauth_provider_t *provider;

    int64_t created_at_ms;
    int64_t expires_at_ms;

    struct oauth_flow *next;
} oauth_flow_t;

typedef struct {
    oauth_flow_t *buckets[FLOW_BUCKETS];
    pthread_mutex_t lock;
} oauth_flow_store_t;

extern oauth_flow_store_t oauth_flows;

const oauth_provider_t* get_oauth_provider(const char* name);
int oauth_flow_store_put(oauth_flow_store_t *store, const oauth_flow_t *flow);
int oauth_flow_store_get(oauth_flow_store_t *store, const char *state, oauth_flow_t *out);
int oauth_pkce_challenge(const char *verifier, char **out_challenge);
int oauth_build_authorize_url(const oauth_provider_t *p, const char *state,
                              const char *nonce, const char *code_challenge, char **out_url);
int oauth_exchange_code_for_id_token(const oauth_flow_t *flow, const char *code, char **out_id_token);
int oauth_extract_google_identity_from_id_token(const oauth_flow_t *flow, const char *id_token,
                                                 char **out_email, char **out_username_seed,
                                                 char **out_provider_user_id);
uint64_t oauth_find_or_create_user(const char *provider, const char *provider_user_id,
                                   const char *email, const char *username_seed);

#endif
