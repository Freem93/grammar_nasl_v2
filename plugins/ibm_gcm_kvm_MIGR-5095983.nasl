#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77003);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/20 14:03:01 $");

  script_cve_id("CVE-2014-3080", "CVE-2014-3081", "CVE-2014-3085");
  script_bugtraq_id(68777, 68779, 68939);
  script_osvdb_id(109380, 109381, 109382, 109383);
  script_xref(name:"EDB-ID", value:"34132");

  script_name(english:"IBM GCM16 / GCM32 Global Console Manager KVM Switch Firmware Version < 1.20.20.23447 Multiple Vulnerabilities");
  script_summary(english:"Checks the firmware version of the Global Console Manager.");

  script_set_attribute(attribute:"synopsis", value:
"The web interface running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote host is an IBM
Global Console Manager KVM switch with a firmware version prior to
1.20.20.23447. It is, therefore, affected by the following 
vulnerabilities :

  - A reflected cross-site scripting attack via 'kvm.cgi'
    or 'avctalert.php'. (CVE-2014-3080)

  - Unauthorized file access via the 'filename' parameter
    of the 'prodtest.php' script. (CVE-2014-3081)

  - Remote code injection via the 'lpre' parameter of the
    'systest.php' script. (CVE-2014-3085)");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_three_potential_vulnerabilities_in_ibm_gcm16_gcm32_global_console_managers_cve_2014_3085_cve_2014_3081_cve_2014_3080?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cafd98b3");
  # http://www-947.ibm.com/support/entry/portal/docdisplay?lndocid=MIGR-5095983
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4046838c");
  script_set_attribute(attribute:"solution", value:"Upgrade to firmware version 1.20.20.23447 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:ibm:avocent_1754_kvm");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:ibm:global_console_manager_16_firmware");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:ibm:global_console_manager_32_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("ibm_gcm_kvm_detect.nbin");
  script_require_keys("Host/IBM/GCM/Version","Host/IBM/GCM/Model");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/IBM/GCM/Version");
model   = get_kb_item_or_exit("Host/IBM/GCM/Model");

cutoff_version = "1.20.0.22575";
fixed_version = "1.20.20.23447";
if (ver_compare(ver:version, fix:cutoff_version, strict:FALSE) <= 0)
{
  set_kb_item(name:"www/0/XSS", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Model                      : ' + model +
      '\n  Installed firmware version : ' + version +
      '\n  Fixed firmware version     : ' + fixed_version +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(port:0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "GCM Firmware", version);
