#TRUSTED 65b5469f9a7104a3cc4f386059c6bcc52b921f717e8179bff0fba9748e2578d95c052ef0b7ad562fc9c67245a84b666ba0ae1f065c1739312d39430f3c2cb8509e174e2090b357f27d75d4b514e6cefa3fd507c0b7b01ef372a3769085eee7cb3e73906a6a72901ff8dacd3e0144aa4e1fb80a48d771501d41c4edd0ab7509c94b55c57982bcec5ca6fb6fd9afeef4a00be976d60eac5f8e8c07e59cb3e9d38f70c5ef08f7aea84d56bc151c64100626ded745d316988fb7ea55e2d5dacca475032cd818383e52326d71a4c015714b77395bd51400feb14003ef27da972b6cbf6a2535b0d888576a76141f03518f95e62163914f07edc54de277543a8eabfb24d90cddc3185b3a2298a0b82487325869fa843f4b59b20f41b518bba84304d3b7c8bb9df8e7add604fcb8eaf845f92f0d691a319d1fd4922e23fe2adff6a11a5157716090baa08544a4a7de3802fb7830265a57e41f55e66b404baec317794a2f750cc166887300687ce631ddff11da045efca751d1109562dde56b3b9849ef0c738f34cc2be6eef14d8f5e90da97f18067fceabcbef4b5bc2f1b04d5490f08490a8256d1e587e6e069c4b213fad7a255593b02d68f7f00e85b2e0972e57167ff1f27ad75622564d3042b4cb71214cf9e312f8d8035e09830536cd694d652f46a86f8619030b628b2d4f5b8a0ccc1c17dc47668332915cfe4b49c115c2b8ebb67
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
# amazon_aws_ami.inc
# Revision: 1.2
#

global_var AWS_AMI_API_ROOT,AWS_AMI_API_HOST,AWS_AMI_API_ITEMS,AWS_AMI_HOST_TAG_BASE,AWS_AMI_KB_BASE;

##
# AMI API Root
##
AWS_AMI_API_ROOT  = "/latest/meta-data/";

##
# AMI API Host
##
AWS_AMI_API_HOST  = "169.254.169.254";

##
# XML Host Tag base
##
AWS_AMI_HOST_TAG_BASE = "aws-instance";

##
# KB Base
##
AWS_AMI_KB_BASE = "Host/AWS/AMI";

##
# API Items with their validation regular expressions
##
AWS_AMI_API_ITEMS = make_array(
  'ami-id'         , "^ami-[A-Za-z0-9]+$",
  'instance-id'    , "^i-[A-Za-z0-9]+$",
  'hostname'       , "^[A-Za-z\-0-9.]+$",
  'local-hostname' , "^[A-Za-z\-0-9.]+$",
  'public-hostname', "^[A-Za-z\-0-9.]+$",
  'local-ipv4'     , "^\d+\.\d+\.\d+\.\d+$",
  'public-ipv4'    , "^\d+\.\d+\.\d+\.\d+$"
);
