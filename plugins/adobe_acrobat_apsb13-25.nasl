#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70342);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/01/19 03:39:41 $");

  script_cve_id("CVE-2013-5325");
  script_bugtraq_id(62888);
  script_osvdb_id(98225);

  script_name(english:"Adobe Acrobat 11.0.4 Crafted PDF File Handling JavaScript Scheme URI Execution (APSB13-25)");
  script_summary(english:"Checks version of Adobe Acrobat");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of Adobe Acrobat on the remote Windows host is affected by
a JavaScript URI scheme execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Adobe Acrobat installed on the remote host is 11.0.4. 
It is, therefore, affected by a flaw in the handling of specially
crafted PDF files.  This can allow an attacker to launch JavaScript URI
schemes."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb13-25.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Acrobat 11.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:'Windows');
  script_copyright(english:'This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.');

  script_dependencies('adobe_acrobat_installed.nasl');
  script_require_keys('SMB/Acrobat/Version');
  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

version = get_kb_item_or_exit("SMB/Acrobat/Version");
version_ui = get_kb_item('SMB/Acrobat/Version_UI');

if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

path = get_kb_item_or_exit('SMB/Acrobat/Path');

# Only versions 11.0.4 are affected
if (ver[0] == 11 && ver[1] == 0 && ver[2] == 4)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : '+path+
      '\n  Installed version : '+version_report+
      '\n  Fixed version     : 11.0.5\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Adobe Acrobat", version_report, path);
