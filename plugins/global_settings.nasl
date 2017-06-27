#TRUSTED 735111912ef93bd812cf69e85ad77cf97058f8fc36a3caaf94b7fee9c1c159bacc290c795fcc75e2ceb23fc7988614f36eaeb11aac8e1bc30e5917ab54e58611147ed0af0fcb3f38bdf85c8a8fe2204fe65365464de71b8bdfe3297978863006ef49e61da97f05bc6be283e074cd0a730dc97cbfb1e0d0cab3bf220fdadd9b0992a576e446e5f0765a3922d8106de21fcee5f34447343cf538778771b674326c5d935e6c15d90dbc2e00cb68c558f7ef522327808d788d2a343ac037134c9c7cab89cf8d5d504374f43568033a0f513e6ed9bd6c85683bea34024d1059876f3060208320ac43ab09024fc1f7d8a087a1803485e566a09929fc565ad945b46fa5222cecfd3209967eb1d92385050fc7b9492a5230ab9e5c34bffbb2be32982eab7fe3f700ee1933852eb236582be0a3c75598dc519449e4a19a8bdfcfd016882b8f814e1ce1e9717fa020927a142c346cbd5e3eaafb130cb459af5d950dcfd8fa90ad0d278d966ce5f97138d5944551f18b0005a8092be76c8abc166210a9ab687722c3fb9ecded4d5961ef6765816194b41308acbe6a76753b64c9ab72e9063708b475f9944ebc20e6cae31e6e281111c8faf236dbd1cb4233d5e4e4a0b9b62cd62bea7cdd96d9fc2685059c13f373a8abf62e307fc62f80851dc987b9a17bb640703d36f0629706d37555ca3ed4f2aa3197f1bfdaf78942f7b8f0d3202d3053
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(12288);
 script_version("1.38");
 script_set_attribute(attribute:"plugin_modification_date", value:"2015/12/16");

 script_name(english:"Global variable settings");
 script_summary(english:"Global variable settings.");

 script_set_attribute(attribute:"synopsis", value:
"Sets global settings.");
 script_set_attribute(attribute:"description", value:
"This plugin configures miscellaneous global variables for Nessus
plugins. It does not perform any security checks but may disable or
change the behavior of others.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/06/29");

 script_set_attribute(attribute:"plugin_type", value:"settings");
 script_set_attribute(attribute:"agent", value:"all");
 script_end_attributes();

 script_category(ACT_SETTINGS);

 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"Settings");

 if ( NASL_LEVEL >= 3200 )
   script_add_preference(name:"Probe services on every port", type:"checkbox", value:"yes");
 script_add_preference(name:"Do not log in with user accounts not specified in the policy", type:"checkbox", value:"no");
 if ( NASL_LEVEL >= 4000 )
  script_add_preference(name:"Enable CGI scanning", type:"checkbox", value:"no");
 else
  script_add_preference(name:"Enable CGI scanning", type:"checkbox", value:"yes");

 script_add_preference(name:"Network type", type:"radio", value:"Mixed (use RFC 1918);Private LAN;Public WAN (Internet)");
 script_add_preference(name:"Enable experimental scripts", type:"checkbox", value:"no");
 script_add_preference(name:"Thorough tests (slow)", type:"checkbox", value:"no");
 script_add_preference(name:"Report verbosity", type:"radio", value:"Normal;Quiet;Verbose");
 script_add_preference(name:"Report paranoia", type:"radio", value:"Normal;Avoid false alarms;Paranoid (more false alarms)");
 script_add_preference(name:"HTTP User-Agent", type:"entry", value:"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)");
 script_add_preference(name:"SSL certificate to use : ", type:"file", value:"");
 script_add_preference(name:"SSL CA to trust : ", type:"file", value:"");
 script_add_preference(name:"SSL key to use : ", type:"file", value:"");
 script_add_preference(name:"SSL password for SSL key : ", type:"password", value:"");
 script_add_preference(name:"Enumerate all SSL ciphers", type:"checkbox", value:"yes");
 script_add_preference(name:"Enable CRL checking (connects to Internet)", type:"checkbox", value:"no");
 script_add_preference(name:"Enable plugin debugging", type:"checkbox", value:"no");

 exit(0);
}

if ( get_kb_item("global_settings/disable_service_discovery")  ) exit(0);
if ( script_get_preference("SSL certificate to use : ") )
 cert = script_get_preference_file_location("SSL certificate to use : ");

if ( script_get_preference("SSL CA to trust : ") )
 ca = script_get_preference_file_location("SSL CA to trust : ");

ciph = script_get_preference("Enumerate all SSL ciphers");
if ( ciph == "no" ) set_kb_item(name:"global_settings/disable_ssl_cipher_neg", value:TRUE);

if ( script_get_preference("SSL key to use : ") )
 key = script_get_preference_file_location("SSL key to use : ");

pass = script_get_preference("SSL password for SSL key : ");

if ( cert && key )
{
 if ( NASL_LEVEL >= 5000 )
 {
  mutex_lock("global_settings_convert");
  if ( get_global_kb_item("/tmp/global_settings_convert") == NULL )
  {
   if ( file_stat(cert) )
   {
    b = fread(cert);
    unlink(cert);
    fwrite(data:b, file:cert);
   }

   if ( file_stat(key) )
   {
    b = fread(key);
    unlink(key);
    fwrite(data:b, file:key);
   }

   if ( !isnull(ca) && file_stat(ca) )
   {
    b = fread(ca);
    unlink(ca);
    fwrite(data:b, file:ca);
   }
   set_global_kb_item(name:"/tmp/global_settings_convert", value:TRUE);
  }
  mutex_unlock("global_settings_convert");
 }

 set_kb_item(name:"SSL/cert", value:cert);
 set_kb_item(name:"SSL/key", value:key);
 if ( !isnull(ca) ) set_kb_item(name:"SSL/CA", value:ca);
 if ( !isnull(pass) ) set_kb_item(name:"SSL/password", value:pass);
}

opt = script_get_preference("Enable CRL checking (connects to Internet)");
if ( opt && opt == "yes" ) set_global_kb_item(name:"global_settings/enable_crl_checking", value:TRUE);

opt = script_get_preference("Enable plugin debugging");
if ( opt && opt == "yes" ) set_kb_item(name:"global_settings/enable_plugin_debugging", value:TRUE);

opt = script_get_preference("Probe services on every port");
if ( opt && opt == "no" ) set_kb_item(name:"global_settings/disable_service_discovery", value:TRUE);

opt = script_get_preference("Do not log in with user accounts not specified in the policy");
if ( opt && opt == "yes" ) set_kb_item(name:"global_settings/supplied_logins_only", value:TRUE);

opt = script_get_preference("Enable CGI scanning");
if ( opt == "no" ) set_kb_item(name:"Settings/disable_cgi_scanning", value:TRUE);

opt = script_get_preference("Enable experimental scripts");
if (! opt || ";" >< opt ) opt = "no";
set_kb_item(name:"global_settings/experimental_scripts", value:opt);
if ( opt == "yes" ) set_kb_item(name:"Settings/ExperimentalScripts", value:TRUE);

opt = script_get_preference("Thorough tests (slow)");
if (! opt || ";" >< opt ) opt = "no";
set_kb_item(name:"global_settings/thorough_tests", value:opt);

if ( opt == "yes" ) set_kb_item(name:"Settings/ThoroughTests", value:TRUE);

opt = script_get_preference("Report verbosity");
if (! opt || ";" >< opt ) opt = "Normal";
set_kb_item(name:"global_settings/report_verbosity", value:opt);

opt = script_get_preference("Debug level");
if (! opt || ";" >< opt ) opt = "0";
set_kb_item(name:"global_settings/debug_level", value:int(opt));

opt = script_get_preference("Report paranoia");
if (! opt || ";" >< opt ) opt = "Normal";
set_kb_item(name:"global_settings/report_paranoia", value:opt);
if (opt == "Paranoid (more false alarms)")
  set_kb_item(name:"Settings/ParanoidReport", value: TRUE);

opt = script_get_preference("Network type");
if (! opt || ";" >< opt ) opt = "Mixed (RFC 1918)";
set_kb_item(name:"global_settings/network_type", value:opt);

opt = script_get_preference("HTTP User-Agent");
if (! opt) opt = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)";
set_kb_item(name:"global_settings/http_user_agent", value:opt);
if ( NASL_LEVEL >= 3000 )	# http_ids_evasion.nasl is disabled
  set_kb_item(name:"http/user-agent", value: opt);

opt = script_get_preference("Host tagging");
if (! opt || ";" >< opt ) opt = "no";
set_kb_item(name:"global_settings/host_tagging", value:opt);
if ( opt == "yes" ) set_kb_item(name:"Settings/HostTagging", value:TRUE);
