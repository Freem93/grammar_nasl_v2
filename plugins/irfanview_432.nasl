#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57560);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/10/30 13:23:40 $");

  script_cve_id("CVE-2011-5233");
  script_bugtraq_id(51132);
  script_osvdb_id(77957);
  script_xref(name:"Secunia", value:"47065");

  script_name(english:"IrfanView < 4.32 Buffer Overflow");
  script_summary(english:"Checks version of IrfanView");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote Windows host is affected by a buffer
overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of IrfanView earlier than
4.32.  As such, it is reportedly affected by a buffer overflow
vulnerability due to the way the application handles TIFF files with
SGILog compressed images fixed.  

A remote, unauthenticated attacker could exploit this flaw to execute
arbitrary code on the remote host subject to the privileges of the
user running the affected application.");
  script_set_attribute(attribute:"see_also", value:"http://www.irfanview.com/main_history.htm");
  script_set_attribute(attribute:"see_also", value:"http://www.irfanview.com/history_old.htm");
  script_set_attribute(attribute:"solution", value:"Upgrade to IrfanView version 4.32 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:irfanview:irfanview");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
  
  script_dependencies("irfanview_installed.nasl");
  script_require_keys("SMB/IrfanView/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit('SMB/IrfanView/Version');
path = get_kb_item_or_exit('SMB/IrfanView/Path');

fix = '4.3.2.0';

if (ver_compare(ver:version, fix:fix) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(get_kb_item('SMB/transport'));
  exit(0);
}
else exit(0, 'The IrfanView '+version+' install is not affected.');
