#
# (C) Tenable Network Security, Inc.
#

# @@NOTE: The output of this plugin should not be changed
#

include("compat.inc");

if (description)
{
  script_id(11936);
  script_version("$Revision: 2.42 $");
  script_cvs_date("$Date: 2017/02/21 18:16:30 $");

  script_name(english:"OS Identification");
  script_summary(english:"Determines the remote operating system.");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to guess the remote operating system.");
  script_set_attribute(attribute:"description", value:
"Using a combination of remote probes (e.g., TCP/IP, SMB, HTTP, NTP,
SNMP, etc.), it is possible to guess the name of the remote operating
system in use. It is also possible sometimes to guess the version of
the operating system.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/12/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"agent", value:"all");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");

  script_dependencies(
    "os_fingerprint_http.nasl",
    "os_fingerprint_html.nasl",
    "os_fingerprint_ldap.nasl",
    "os_fingerprint_mdns.nasl",
    "os_fingerprint_misc.nasl",
    "os_fingerprint_ntp.nasl",
    "os_fingerprint_sinfp.nasl",
    "os_fingerprint_sip.nasl",
    "os_fingerprint_smb.nasl",
    "os_fingerprint_smtp.nasl",
    "os_fingerprint_snmp.nasl",
    "os_fingerprint_snmp_sysobjectid.nasl",
    "os_fingerprint_snmp_software.nasl",
    "os_fingerprint_sslcert.nasl",
    "os_fingerprint_ftp.nasl",
    "os_fingerprint_xprobe.nasl",
    "os_fingerprint_msrprc.nasl",
    "os_fingerprint_uname.nasl",
    "os_fingerprint_ssh.nasl",
    "os_fingerprint_linux_distro.nasl",
    "os_fingerprint_telnet.nasl",
    "os_fingerprint_upnp.nasl",
    "os_fingerprint_afp.nasl",
    "os_fingerprint_hnap.nasl",
    "cisco_gss_version.nasl",
    "cisco_ios_version.nasl",
    "cisco_ios_xe_version.nasl",
    "cisco_ios_xr_version.nasl",
    "cisco_nxos_version.nasl",
    "cisco_esa_version.nasl",
    "cisco_sma_version.nasl",
    "cisco_wsa_version.nasl",
    "lockdown_detect.nasl",
    "os_fingerprint_nativelanmanager.nasl",
    "os_fingerprint_ssh_netconf.nasl",
    "os_fingerprint_rdp.nbin",
    "ibmi_detect.nbin"
  );
  exit(0);
}

include("misc_func.inc");

# Dynamically makes fingerprint method list
# We need both once with Confidence and Fingerprints,
# so it will be best to just grab everything.
methods = make_list();

OS_kbs = get_kb_list_or_exit("Host/OS/*");

foreach kb_name (keys(OS_kbs))
{
  matches = eregmatch(pattern:"Host/OS/(\w+)", string:kb_name);
  if (isnull(matches)) continue;

  methods = make_list(methods, matches[1]);
}

methods = list_uniq(methods);

function get_best_match()
{
 local_var meth;
 local_var best_match;
 local_var best_score;
 local_var best_type;
 local_var best_meth;
 local_var best_meth1;
 local_var kb;
 local_var score;
 local_var ret;
 local_var len, len2;
 local_var kb_confidence;

 foreach meth (methods)
 {
  kb = get_kb_item("Host/OS/" + meth);
  if( kb )
  {
   score = get_kb_item("Host/OS/" + meth + "/Confidence");
   if ( isnull(score) ) continue;
   if ( score < best_score ) continue;
   best_score = score;
   best_meth  = meth;
   best_match  = kb;
   best_type  = get_kb_item("Host/OS/" + meth + "/Type");
  }
 }

 if (isnull(best_meth))  return NULL;

 # Try to find something more precise
 best_meth1 = best_meth;
 len = strlen(best_match);
 foreach meth (methods)
   if (meth != best_meth)
   {
     kb = get_kb_item("Host/OS/" + meth);
     if ( '\n' >< kb ) continue;
     kb_confidence = get_kb_item("Host/OS/" + meth + "/Confidence");
     len2 = strlen(kb);
     if(len2 > len && kb_confidence >= 80 && best_match >< kb )
     {
       len = len2;
       score = kb_confidence;
       # best_score = score;
       best_meth  = meth;
       best_match  = kb;
       best_type  = get_kb_item("Host/OS/" + meth + "/Type");
     }
   }

  ret["meth"] = best_meth;
  if (best_meth != best_meth1) ret["meth1"] = best_meth1;
  ret["confidence"] = best_score;
  ret["os"] = best_match;
  ret["type"] = best_type;
  return ret;
}

function get_fingerprint()
{
 local_var meth;
 local_var ret;
 local_var kb;

 foreach meth ( methods )
 {
  kb = get_kb_item("Host/OS/" + meth + "/Fingerprint");
  if ( kb )
  {
    if ( get_kb_item("Host/OS/" + meth) )
     ret += meth + ':' + kb + '\n';
    else
     ret += meth + ':!:' + kb + '\n';
  }
 }
 return ret;
}

function missing_fingerprints()
{
 local_var meth;
 local_var flag;

 flag = 0;
 foreach meth ( methods )
 {
  if ( meth == "HTTP" || meth == "ICMP" || meth == "Misc" || meth == "SSH" || meth == "telnet" || meth == "SSLcert" ) continue;
  if ( get_kb_item("Host/OS/" + meth + "/Fingerprint") &&
      !get_kb_item("Host/OS/" + meth) )  flag ++;
 }

 if ( flag ) return 1;
 else return 0;
}

ret = get_best_match();

if ( ! isnull(ret) )
{
 report = '\nRemote operating system : ' + ret["os"];
 report += '\nConfidence level : ' + ret["confidence"];
 report += '\nMethod : ' + ret["meth"] + '\n';
 if (ret["meth1"])
 report += '\nPrimary method : ' + ret["meth1"] + '\n';

 if ( missing_fingerprints() )
 {
  fg = get_fingerprint();
  if ( fg ) report +=
    '\n' + 'Not all fingerprints could give a match. If you think some or all of' +
    '\n' + 'the following could be used to identify the host\'s operating system,' +
    '\n' + 'please email them to os-signatures@nessus.org. Be sure to include a' +
    '\n' + 'brief description of the host itself, such as the actual operating' +
    '\n' + 'system or product / model names.' +
    '\n' +
    '\n' + fg;
 }

 # The text of the plugin output in the following lines must not be modified to avoid breaking SC
 if ( '\n' >!< ret["os"] )
  report += '\n \nThe remote host is running ' + ret["os"];
 else
  report += '\n \nThe remote host is running one of these operating systems : \n' + ret["os"];

 if ( defined_func("report_xml_tag") )
 {
  report_xml_tag(tag:"operating-system", value:ret["os"]);
  if ( !isnull(ret["type"]) ) report_xml_tag(tag:"system-type", value:ret["type"]);
 }

 security_note(port:0, extra:report);
 if ( !isnull(ret["os"]) ) set_kb_item(name:"Host/OS", value:ret["os"]);
 if ( !isnull(ret["confidence"]) ) set_kb_item(name:"Host/OS/Confidence", value:ret["confidence"]);
 if ( ! isnull(ret["type"]) ) set_kb_item(name:"Host/OS/Type", value:ret["type"]);

 exit(0);
}
else if ( missing_fingerprints() )
{
 fg = get_fingerprint();
 if ( fg ) set_kb_item(name:"Host/OS/Fingerprint/Fail", value:fg);
}
