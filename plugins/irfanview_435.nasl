#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63059);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/20 14:03:01 $");

  script_cve_id("CVE-2009-5022");
  script_bugtraq_id(47338);
  script_osvdb_id(72260, 87281);
  script_xref(name:"EDB-ID", value:"22680");
  script_xref(name:"EDB-ID", value:"22681");

  script_name(english:"IrfanView < 4.35 Multiple Heap-Based Buffer Overflows");
  script_summary(english:"Checks version of IrfanView");

  script_set_attribute(attribute:"synopsis", value:
"A graphic viewer installed on the remote host is affected by multiple
buffer overflow vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of IrfanView prior to
version 4.35.  It is, therefore, reportedly affected by the following
vulnerabilities :

  - An error exists related to 'ImageWidth' value handling
    in JPEG compressed TIFF images.

  - An error exists related to 'End of Line' marker handling
    in RLE compressed BMP images.

These vulnerabilities could allow heap-based buffer overflows, which
could lead to arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"http://www.irfanview.com/main_history.htm");
  script_set_attribute(attribute:"see_also", value:"http://www.irfanview.com/history_old.htm");
  # http://www.protekresearchlab.com/index.php?option=com_content&view=article&id=64&Itemid=64
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ffbdf43");
  # http://www.protekresearchlab.com/index.php?option=com_content&view=article&id=65&Itemid=65
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb817723");
  script_set_attribute(attribute:"solution", value:"Upgrade to IrfanView version 4.35 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:irfanview:irfanview");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
  
  script_dependencies("irfanview_installed.nasl");
  script_require_keys("SMB/IrfanView/Version");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");

version = get_kb_item_or_exit('SMB/IrfanView/Version');
path = get_kb_item_or_exit('SMB/IrfanView/Path');

fix = '4.3.5.0';

if (ver_compare(ver:version, fix:fix) == -1)
{
  port = get_kb_item('SMB/transport');
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
