#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72349);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/02/06 02:42:19 $");

  script_name(english:"McAfee VirusScan Enterprise 8.8 < 8.8 Patch 1 DoS");
  script_summary(english:"Checks version of McAfee VSE.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has an antivirus application that is affected
by a denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host has a version of McAfee VirusScan Enterprise
(VSE) 8.8 prior to 8.8 Patch 1. It is, therefore, affected by a denial
of service vulnerability due to a flaw in Self Protection. Malicious
software can change the NTFS folder permissions on VSE folders and
disable the software."
  );
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=KB72032");
  script_set_attribute(attribute:"solution", value:"Upgrade to VSE 8.8 Patch 1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:virusscan_enterprise");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "mcafee_installed.nasl");
  script_require_keys("Antivirus/McAfee/installed");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("Antivirus/McAfee/installed");
product_name = get_kb_item_or_exit("Antivirus/McAfee/product_name");
version = get_kb_item_or_exit("Antivirus/McAfee/product_version");

if ("McAfee VirusScan Enterprise" >!< product_name) audit(AUDIT_INST_VER_NOT_VULN, product_name);

# If not 8.8, then not vuln.
if (version !~ "^8\.8\..*$") audit(AUDIT_INST_VER_NOT_VULN, product_name, version);

# If before Patch 1, then vuln.
fix = "8.8.0.849";

if (ver_compare(ver: version, fix: fix, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix + '\n';

    security_hole(port:port, extra:report);
    exit(0);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, product_name, version);
