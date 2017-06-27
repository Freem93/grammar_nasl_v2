#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77002);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/08/05 19:42:14 $");

  script_cve_id("CVE-2013-0526");
  script_bugtraq_id(61816);
  script_osvdb_id(96389);

  script_name(english:"IBM GCM16 / GCM32 Global Console Manager KVM Switch Firmware Version < 1.20.0.22575 Remote Code Execution");
  script_summary(english:"Checks the firmware version of the Global Console Manager.");

  script_set_attribute(attribute:"synopsis", value:
"The web interface running on the remote host is affected by a remote
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote host is an IBM
Global Console Manager KVM switch with a firmware version prior to
1.20.0.22575. It is, therefore, affected by a remote code execution
vulnerability that could allow an authenticated attacker to execute
commands as root via the 'ping.php' script's 'count' and 'size'
parameters.");
  # http://www-947.ibm.com/support/entry/portal/docdisplay?lndocid=MIGR-5093509
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1bdd4878");
  script_set_attribute(attribute:"solution", value:"Upgrade to firmware version 1.20.0.22575 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:ibm:avocent_1754_kvm");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:ibm:global_console_manager_16_firmware");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:ibm:global_console_manager_32_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("ibm_gcm_kvm_detect.nbin");
  script_require_keys("Host/IBM/GCM/Version","Host/IBM/GCM/Model");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/IBM/GCM/Version");
model   = get_kb_item_or_exit("Host/IBM/GCM/Model");

cutoff_version = "1.18.0.22011";
fixed_version = "1.20.0.22575";
if (ver_compare(ver:version, fix:cutoff_version, strict:FALSE) <= 0)
{
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
