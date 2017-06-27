#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72395);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/02/08 00:47:21 $");

  script_cve_id("CVE-2013-5351", "CVE-2013-6932");
  script_bugtraq_id(64388, 64561);
  script_osvdb_id(101064, 101065);

  script_name(english:"IrfanView < 4.37 Multiple Buffer Overflow Vulnerabilities");
  script_summary(english:"Checks version of IrfanView");

  script_set_attribute(attribute:"synopsis", value:
"A graphic viewer installed on the remote host is affected by multiple
buffer overflow vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of IrfanView prior to
version 4.37.  It is, therefore, reportedly affected by multiple buffer
overflow vulnerabilities :

  - A boundary error exists when handling the LZW code
    stream within GIF files that could lead to arbitrary
    code execution. (CVE-2013-5351)

  - An error exists in the Thumbnail 'tooltips' feature when
    viewing a specially crafted file contained in a folder
    named using multi-byte characters in the Thumbnails
    window, such as when handling Japanese folder names.
    Exploitation of this issue could result in arbitrary 
    code execution. (CVE-2013-6932)");
  script_set_attribute(attribute:"see_also", value:"http://www.irfanview.com/main_history.htm");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2013-13/");
  script_set_attribute(attribute:"see_also", value:"http://jvn.jp/en/jp/JVN63194482/index.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to IrfanView version 4.37 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:irfanview:irfanview");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("irfanview_installed.nasl");
  script_require_keys("SMB/IrfanView/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit('SMB/IrfanView/Version');
path = get_kb_item_or_exit('SMB/IrfanView/Path');

fix = '4.3.7.0';
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
