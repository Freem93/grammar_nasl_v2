#TRUSTED 6dae28f21b5346fca7460a8618b7c922574a863b721e3d3184293f2cd2f96247ad6a44a06307d3b808f79ea9de61b71bd64af1a0ced90b49d4b551ad3d842ca83e3674ba18fa7aeef4f169fb00ff336750c89945e4904daaf698d9a00fccc6e784d1263a4044b6b9a69679d1f40f78566f6afa825e2f863565a22126aed82ac46b16808cb434fab9e96acce54fbd14aa816d920d24b4b97008f58e4a2a257ef19a16808277b016ca268b5e505542c1e57508a965aac1818600ca3ec6a47b9570dee29696f89401e870cb50065ecf0697c2d5bd4bbaa7b71668409df9c10abaea6ea8585f6b82aa542fcf78b43e6e9f6cee9183412158fcdde870fae2728f038cdf3a6983c35e56b6c3f65e785364863a0a2e127337358d0c877027a0beb01bb8cafd994977b82fc25bf6d81e8041fb4331c839c18d60cc78bdf1a555d7a14afc3efa1fe6b0da99efc4f2b0831acfc2682061de0413bf077eb97254047b4938bf4a0e28835d7fd299f77f33f16cc603d07e7079da6c225ec24f346ed7b6776b985cb637094f2083479a8e1cf75b6fb1d2c79cdf431ba2f95bbcd71426128007f874112e1e4ddae1485b18485df33da39470cd543c547e4ca9a4afefcab27ff532ee06ea3539e2419292e9fcc7b7f29cba71ce21375839457ec0023273eb2c1dcfd34ebf135ad378f7a43ec04fb40eef6ec609fc7847f749f03e5430870059a31d
#
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
#
# @NOGPL@
#
# google_compute_engine.inc
# Revision: 1.0
#

global_var GOOGLE_COMPUTE_ENGINE_API_ROOT, GOOGLE_COMPUTE_ENGINE_API_HOST;
global_var GOOGLE_COMPUTE_ENGINE_API_ITEMS, GOOGLE_COMPUTE_ENGINE_HOST_TAG_BASE;
global_var GOOGLE_COMPUTE_ENGINE_KB_BASE;

# for grabbing IP addresses
global_var GOOGLE_COMPUTE_ENGINE_NETWORK_INTERFACES_LIST;
global_var GOOGLE_COMPUTE_ENGINE_IP;
global_var GOOGLE_COMPUTE_ENGINE_ACCESS_CONFIGS_LIST;
global_var GOOGLE_COMPUTE_ENGINE_EXTERNAL_IP;

##
# GOOGLE_COMPUTE_ENGINE API Root
##
GOOGLE_COMPUTE_ENGINE_API_ROOT  = "/computeMetadata/v1/instance/";

##
# GOOGLE_COMPUTE_ENGINE API Host
##
GOOGLE_COMPUTE_ENGINE_API_HOST  = "metadata.google.internal";

##
# XML Host Tag base
##
GOOGLE_COMPUTE_ENGINE_HOST_TAG_BASE = "google-compute-engine-instance";

##
# KB Base
##
GOOGLE_COMPUTE_ENGINE_KB_BASE = "Host/Google Compute Engine";

##
# API Items with their validation regular expressions
##
GOOGLE_COMPUTE_ENGINE_API_ITEMS = make_array(
  'name'                , "^[A-Za-z\-0-9.]+$",
  'id'                  , "^[0-9]+$",
  'hostname'            , "^[A-Za-z\-0-9.]+$"
);

# For grabbing IP addresses. X and Y are indexes.
# Internals are at /network-interfaces/X/ip
# Externals are at /network-interfaces/X/access-configs/Y/external-ip
GOOGLE_COMPUTE_ENGINE_NETWORK_INTERFACES_LIST = "network-interfaces/";
GOOGLE_COMPUTE_ENGINE_IP = "ip";
GOOGLE_COMPUTE_ENGINE_ACCESS_CONFIGS_LIST = "access-configs/";
GOOGLE_COMPUTE_ENGINE_EXTERNAL_IP = "external-ip";
