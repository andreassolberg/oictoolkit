'use strict';

const _ = require('lodash');

const COMMON_METADATA = [
  'signing_keys',
  'signing_keys_uri',
  'metadata_statements',
  'metadata_statement_uris',
  'signed_jwks_uri'
];

const CLIENT_METADATA = [
  'application_type',
  'client_id',
  'client_name',
  'client_secret',
  'client_secret_expires_at',
  'client_uri',
  'contacts',
  'default_acr_values',
  'default_max_age',
  'grant_types',
  'id_token_encrypted_response_alg',
  'id_token_encrypted_response_enc',
  'id_token_signed_response_alg',
  'initiate_login_uri',
  'jwks',
  'jwks_uri',
  'logo_uri',
  'policy_uri',
  'post_logout_redirect_uris',
  'redirect_uris',
  'registration_access_token',
  'registration_client_uri',
  'request_object_encryption_alg',
  'request_object_encryption_enc',
  'request_object_signing_alg',
  'request_uris',
  'require_auth_time',
  'response_types',
  'sector_identifier_uri',
  'subject_type',
  'token_endpoint_auth_method',
  'token_endpoint_auth_signing_alg',
  'tos_uri',
  'userinfo_encrypted_response_alg',
  'userinfo_encrypted_response_enc',
  'userinfo_signed_response_alg',
];

const CLIENT_METADATA_EXTRA = [
  'scopes',
  'claims',
];


const ISSUER_METADATA = [
  'acr_values_supported',
  'authorization_endpoint',
  'check_session_iframe',
  'claims_parameter_supported',
  'claims_supported',
  'claim_types_supported',
  'code_challenge_methods_supported',
  'end_session_endpoint',
  'grant_types_supported',
  'id_token_encryption_alg_values_supported',
  'id_token_encryption_enc_values_supported',
  'id_token_signing_alg_values_supported',
  'issuer',
  'jwks_uri',
  'registration_endpoint',
  'request_object_encryption_alg_values_supported',
  'request_object_encryption_enc_values_supported',
  'request_object_signing_alg_values_supported',
  'request_parameter_supported',
  'request_uri_parameter_supported',
  'require_request_uri_registration',
  'response_modes_supported',
  'response_types_supported',
  'scopes_supported',
  'subject_types_supported',
  'token_endpoint',
  'token_endpoint_auth_methods_supported',
  'token_endpoint_auth_signing_alg_values_supported',
  'token_introspection_endpoint',
  'introspection_endpoint',
  'token_revocation_endpoint',
  'revocation_endpoint',
  'userinfo_encryption_alg_values_supported',
  'userinfo_encryption_enc_values_supported',
  'userinfo_endpoint',
  'userinfo_signing_alg_values_supported',
];

const JWT_PROPERTIES = [
  'iss',
  'sub',
  'aud',
];

const METADATA_STATEMENT = _.concat(COMMON_METADATA, CLIENT_METADATA, CLIENT_METADATA_EXTRA, ISSUER_METADATA, JWT_PROPERTIES);

module.exports.CLIENT_METADATA = CLIENT_METADATA;
module.exports.ISSUER_METADATA = ISSUER_METADATA;
module.exports.METADATA_STATEMENT = METADATA_STATEMENT;
