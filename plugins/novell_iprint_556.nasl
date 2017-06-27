#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51367);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/23 20:31:34 $");

  script_cve_id("CVE-2010-4321");
  script_bugtraq_id(44966, 45301);
  script_osvdb_id(69357);
  script_xref(name:"EDB-ID", value:"16014");

  script_name(english:"Novell iPrint Client < 5.56 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Novell iPrint Client"); 
 
  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains an application that is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The version of Novell iPrint Client installed on the remote host is
earlier than 5.56.  Such versions are reportedly affected by one or
more of the following vulnerabilities that can allow for arbitrary
code execution :

  - The iPrint ActiveX control fails to sanitize input to 
    the 'GetDriverSettings2()' method in the 'ienipp.ocx' 
    component before copying it into a fixed-length buffer 
    on the stack. (ZDI-10-256 / CVE-2010-4321)

  - There is a stack-based buffer overflow in both the
    Netscape (Firefox) and ActiveX (Internet Explorer) 
    plugin components ('npnipp.dll' and 'ienipp.ocx') due to
    their failure to sufficiently validate the size of a
    printer-state-reasons status response. (ZDI-10-295)

  - Buffer overflows exist in both the Netscape (Firefox) 
    and ActiveX (Internet Explorer) plugin components 
    ('npnipp.dll' and 'ienipp.ocx') due to their failure to 
    sufficiently validate the size of an IPP response from 
    a user provided printer-url. (ZDI-10-296 and ZDI-10-299)

  - The 'nipplib.dll component, as used by both types of 
    browser plugins, does not properly handle the value of
    the Location response header in an HTTP 301 response 
    when copying it into a buffer of fixed size.
    (ZDI-10-297)

  - A stack-based buffer overflow exists in the 'npnipp.dll'
    Mozilla browser plugin because it fails to validate a 
    user input to a call-back-url before passing it to a 
    urlencode function and copying the result into a 
    fixed-length buffer. (ZDI-10-298)

  - The 'nipplib.dll component, as used by both types of 
    browser plugins, does not properly handle the value of
    the Connection response header in an HTTP response when
    copying it into a stack-based buffer of fixed size. 
    (ZDI-10-300)"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.zerodayinitiative.com/advisories/ZDI-10-256"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.zerodayinitiative.com/advisories/ZDI-10-295"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.zerodayinitiative.com/advisories/ZDI-10-296"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.zerodayinitiative.com/advisories/ZDI-10-297"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.zerodayinitiative.com/advisories/ZDI-10-298"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.zerodayinitiative.com/advisories/ZDI-10-299"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.zerodayinitiative.com/advisories/ZDI-10-300"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/fulldisclosure/2010/Nov/213"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/fulldisclosure/2010/Dec/642"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/fulldisclosure/2010/Dec/643"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/fulldisclosure/2010/Dec/644"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/fulldisclosure/2010/Dec/645"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/fulldisclosure/2010/Dec/646"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/fulldisclosure/2010/Dec/647"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://download.novell.com/Download?buildid=JV7fd0tFHHM~"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Novell iPrint Client 5.56 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Novell iPrint Client ActiveX Control Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:iprint");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("novell_iprint_532.nasl");
  script_require_keys("SMB/Novell/iPrint/Version");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


kb_base = "SMB/Novell/iPrint/";

version = get_kb_item_or_exit(kb_base+"Version");
version_ui = get_kb_item_or_exit(kb_base+"Version_UI");
dll = get_kb_item_or_exit(kb_base+"DLL");

fixed_version = "5.5.6.0";
fixed_version_ui = "5.56";

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  if (report_verbosity > 0)
  {
    path = get_kb_item(kb_base+"Path");
    if (isnull(path)) path = 'n/a';

    report =
      '\n  File              : '+dll+
      '\n  Installed version : '+version_ui+
      '\n  Fixed version     : '+fixed_version_ui+'\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0, "The host is not affected since Novell iPrint Client "+version_ui+" is installed.");
