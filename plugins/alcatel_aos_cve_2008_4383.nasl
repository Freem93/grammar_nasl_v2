#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69790);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/10/07 13:30:46 $");

  script_cve_id("CVE-2008-4383");
  script_bugtraq_id(30652);
  script_osvdb_id(47586);
  script_xref(name:"IAVB", value:"2011-B-0141");

  script_name(english:"Alcatel-Lucent OmniSwitch Series Agranat-Embweb Management Server Session Cookie Handling Remote Overflow");
  script_summary(english:"Checks the AOS version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Alcatel OmniSwitch device is affected by a buffer overflow
vulnerability in its web server.  An attacker could exploit it to gain
control of the remote device.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/Aug/238");
  # http://www3.alcatel-lucent.com/security/psirt/statements/2008002/OmniSwitch.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb316c34");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Alcatel Security
Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:alcatel-lucent:omniswitch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alcatel:aos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"General");

  script_dependencies("ssh_get_info.nasl", "http_version.nasl");
  script_require_keys("Host/AOS/show_microcode");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function vers_cmp()
{
 local_var a, b, i;
 local_var m;

 a = _FCT_ANON_ARGS[0];
 b = _FCT_ANON_ARGS[1];
 a = split(a, sep:".", keep:FALSE);
 b = split(b, sep:".", keep:FALSE);
 m = max_index(a);
 if ( max_index(b) < m ) m = max_index(b);

 for ( i = 0 ; i < m; i ++ )
 {
  if ( a[i] != b[i] )
        return int(a[i]) - int(b[i]);
 }


 return max_index(a) - max_index(b);
}


version = get_kb_item_or_exit("Host/AOS/show_microcode");

port = get_http_port(default:80);
res = get_http_banner(port:port);
if ( !res || "Server: Agranat-EmWeb" >!< res ) exit(1, "Wrong web server running.");

os = egrep(pattern:"^[A-Za-z0-9]+os\.img", string:version);
if (! os) exit(1, "The AOS microcode output does not appear to include an OS image file.");

# Gos.img           6.4.5.402.R02    1973103 Alcatel-Lucent OS
vers = preg_replace(pattern:"^[A-Za-z0-9]+os\.img\s+([^\s]+).*", string:chomp(os), replace:"\1");
vers -= "R";


array = split(vers);
#
# The Problem has been fixed in the following maintenance AoS Releases:
# 5.4.1.429.R01 and above
# 5.1.6.463.R02 and above
# 6.1.3.965.R01 and above
# 6.1.5.595.R01 and above
# 6.3.1.966.R01 and above

if (
  (vers_cmp(vers, "5.4.0.0.0") > 0 && vers_cmp(vers, "5.4.1.429.1") < 0) ||
  (vers_cmp(vers, "5.1.0.0.0") > 0 && vers_cmp(vers, "5.1.6.463.2") < 0) ||
  (vers_cmp(vers, "6.1.3.0.0") > 0 && vers_cmp(vers, "6.1.3.965.1") < 0) ||
  (vers_cmp(vers, "6.1.5.0.0") > 0 && vers_cmp(vers, "6.1.5.595.1") < 0) ||
  (vers_cmp(vers, "6.3.0.0.0") > 0 && vers_cmp(vers, "6.3.1.966.1") < 0)
) security_hole(port:0);
