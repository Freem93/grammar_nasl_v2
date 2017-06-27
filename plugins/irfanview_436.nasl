#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68888);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/07/15 21:02:43 $");

  script_cve_id("CVE-2013-3486");
  script_bugtraq_id(61000);
  script_osvdb_id(93753, 94907);

  script_name(english:"IrfanView < 4.36 Multiple Vulnerabilities");
  script_summary(english:"Checks version of IrfanView");

  script_set_attribute(attribute:"synopsis", value:
"A graphic viewer installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of IrfanView prior to
version 4.36.  It is, therefore, reportedly affected by multiple
vulnerabilities :

  - A heap-based buffer overflow vulnerability exists when
    parsing ANI images.  An attacker can exploit this issue
    with a specially crafted ANI file, potentially leading
    to arbitrary code execution.

  - A flaw exists where DCX file headers are not properly
    sanitized, which could potentially lead to a denial of
    service.

  - An integer overflow vulnerability exists in the FlashPix
    Plugin (Fpx.dll) when handling sections of Summary
    Information Property sets, which could lead to arbitrary
    code execution.");
  script_set_attribute(attribute:"see_also", value:"http://www.irfanview.com/main_history.htm");
  script_set_attribute(attribute:"see_also", value:"http://www.irfanview.com/history_old.htm");
  script_set_attribute(attribute:"see_also", value:"http://www.fuzzmyapp.com/advisories/FMA-2013-008/FMA-2013-008-EN.xml");
  script_set_attribute(attribute:"see_also", value:"http://www.fuzzmyapp.com/advisories/FMA-2012-028/FMA-2012-028-EN.xml");
  script_set_attribute(attribute:"see_also", value:"https://secunia.com/advisories/53579/");
  script_set_attribute(attribute:"solution", value:"Upgrade to IrfanView version 4.36 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:irfanview:irfanview");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("irfanview_installed.nasl");
  script_require_keys("SMB/IrfanView/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit('SMB/IrfanView/Version');
path = get_kb_item_or_exit('SMB/IrfanView/Path');

fix = '4.3.6.0';
if (ver_compare(ver:version, fix:fix) == -1)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Irfanview", version, path);
