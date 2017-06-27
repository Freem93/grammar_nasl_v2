#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(59178);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2012/07/19 19:20:54 $");
  
  script_cve_id("CVE-2012-0778");
  script_bugtraq_id(53419);
  script_osvdb_id(81753);
  script_xref(name:"Secunia", value:"47116");

  script_name(english:"Adobe Flash Professional for Mac <= 11.5.1.349 JPG Object Dimension Memory Allocation FLA File Handling Remote Overflow (APSB12-12)");
  script_summary(english:"Checks version of Adobe Flash Professional");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has a multimedia authoring application that
is affected by a code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, at least one instance of Adobe Flash
Professional on the remote Mac OS X host is less than or equal to
11.5.1.349.  It is, therefore, reportedly affected by an integer
overflow error in Flash.exe when allocating memory to process a JPG
object using its image dimensions.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-12.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Professional CS5 11.5.2.349, Flash 
Professional CS6, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_cs");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("macosx_flash_professional_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Adobe Flash Professional/Installed");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit('Host/local_checks_enabled');

os = get_kb_item('Host/MacOSX/Version');
if (!os) audit(AUDIT_OS_NOT, 'Mac OS X');

kb_base = 'MacOSX/Adobe Flash Professional';
get_kb_item_or_exit(kb_base + '/Installed');

versions = get_kb_list(kb_base+'/*/Version');
if (isnull(versions)) exit(1, 'The \''+kb_base+'/*/Version\' KB list is missing.');

info = '';
info2 = '';

foreach install (sort(keys(versions)))
{
  path = '/Applications' + (install - kb_base - '/Version');

  version = versions[install];

  if (ver_compare(ver:version, fix:'11.5.1.349') <= 0)
  {
    info += 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 11.5.2.349 / 12.0.0.481\n';
  }
  else info2 += ' and ' + version;
}

if (info)
{
  if (report_verbosity > 0) security_hole(port:0, extra:info);
  else security_hole(0);

  exit(0);
}

if (info2)
{
  info2 -= ' and ';
  if (' and ' >< info2) be = 'are';
  else be = 'is';

  exit(0, 'The host is not affected since Adobe Flash Professional ' + info2 + ' ' + be + ' installed.');
}
else exit(1, 'Unexpected error - \'info2\' is empty.');
