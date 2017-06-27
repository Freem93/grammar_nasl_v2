#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91991);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/07/13 14:38:01 $");

  script_osvdb_id(139934);
  script_xref(name:"MCAFEE-SB", value:"SB10161");

  script_name(english:"McAfee Email Gateway File Attachment Name NULL Character Handling Filter Bypass (SB10161)");
  script_summary(english:"Checks the MEG version.");

  script_set_attribute(attribute:"synopsis", value:
"An email proxy server running on the remote host is affected by a
filter bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The McAfee Email Gateway (MEG) application running on the remote host
is affected by a flaw when processing email file attachments due to a
failure to remove NULL characters from the raw header value before it
is decoded. An unauthenticated, remote attacker can exploit this, via
a crafted file attachment, to bypass file filters and send arbitrary
files to the recipient.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10161");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant hotfix referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mcafee:email_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_email_gateway_version.nbin");
  script_require_keys("Host/McAfeeSMG/name", "Host/McAfeeSMG/version", "Host/McAfeeSMG/patches");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = get_kb_item_or_exit("Host/McAfeeSMG/name");
version = get_kb_item_or_exit("Host/McAfeeSMG/version");
patches = get_kb_item_or_exit("Host/McAfeeSMG/patches");

# if not 7.6.x, not affected
if (version !~ "^7\.6") audit(AUDIT_INST_VER_NOT_VULN, version);

# fix version comes from patch/hotfix version/build
# e.g. MEG-7.6.404h1128596-3334.102.zip
fix = "7.6.3334.102";
hotfix = "7.6.404h1128596-3334.102";

# if version > fix, not affected
if (ver_compare(ver:version, fix:fix, strict:FALSE) > 0) audit(AUDIT_INST_VER_NOT_VULN, version);

# if patch installed, not affected
if (hotfix >< patches) audit(AUDIT_PATCH_INSTALLED, hotfix, app_name, version);

# report
port = 0;
report = '\n' + app_name + ' ' + version + ' is missing hotfix ' + hotfix + '.\n';
security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
