#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70498);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/10/23 00:38:09 $");

  script_cve_id("CVE-2013-3693");
  script_bugtraq_id(62920);
  script_osvdb_id(98298);
  script_xref(name:"IAVB", value:"2013-B-0118");

  script_name(english:"BlackBerry Enterprise Service Remote Code Execution (KB35139)");
  script_summary(english:"Checks version of BlackBerry Enterprise Service");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has an application that is affected by a remote
code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the BlackBerry Enterprise Service (BES)
install on the remote host is older than 10.1.3. Such versions may be
affected by a remote code execution vulnerability in its Universal
Device Service (UDS) component because it does not properly restrict
access to the JBoss Remote Method Invocation (RMI) interface.  A
remote attacker within the adjacent network and with knowledge of the
address of that component could leverage this issue to upload
arbitrary packages via a request to port 1098 and then execute
code as the BES or UDS administration service account.

There are multiple workarounds detailed in the BlackBerry advisory
if updating BlackBerry Enterprise Service as a whole is not
possible. If any of these workarounds have been applied, this
finding may be a false positive."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.blackberry.com/btsc/KB35139");
  script_set_attribute(
    attribute:"solution",
    value:
"Update to BlackBerry Enterprise Service 10.1.3 or later or apply
a workaround detailed in the advisory."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:blackberry:blackberry_enterprise_service");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("blackberry_es_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "BlackBerry_ES/Product", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

product = get_kb_item_or_exit("BlackBerry_ES/Product");
version = get_kb_item_or_exit("BlackBerry_ES/Version");
path = get_kb_item_or_exit("BlackBerry_ES/Path");

if ("BlackBerry Enterprise Service" >!< product)
  audit(AUDIT_NOT_INST, "BlackBerry Enterprise Service");

fix = "10.1.3";
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Product              : ' + product +
      '\n  Path                 : ' + path +
      '\n  Installed version    : ' + version +
      '\n  Fixed version        : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "BlackBerry Enterprise Service", version, path);
