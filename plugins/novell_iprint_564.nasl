#
# (C) Tenable Network Security, Inc.
#


if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(54988);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2011/10/24 19:37:28 $");

  script_cve_id(
    "CVE-2011-1699",
    "CVE-2011-1700",
    "CVE-2011-1701",
    "CVE-2011-1702",
    "CVE-2011-1703",
    "CVE-2011-1704",
    "CVE-2011-1705",
    "CVE-2011-1706",
    "CVE-2011-1707",
    "CVE-2011-1708"
  );
  script_bugtraq_id(48124);
  script_osvdb_id(73239);
  script_xref(name:"Secunia", value:"44811");

  script_name(english:"Novell iPrint Client < 5.64 Multiple Vulnerabilities");
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
earlier than 5.64.  Such versions are reportedly affected by one or
more of the following vulnerabilities in the nipplib.dll component, as
used by both types of browser plugins, that can allow for arbitrary
code execution :

  - The uri parameter from user specified printer-url is
    not properly handled before passing it to a fixed-length
    buffer on the heap. (ZDI-11-172 / CVE-2011-1699)
  
  - The profile-time parameter from the user specified
    printer-url is not properly handled before passing it to
    a fixed-length buffer on the heap. 
    (ZDI-11-173 / CVE-2011-1700)

  - The profile-name parameter from the user specified
    printer-url is not properly handled before passing it to
    a fixed-length buffer on the heap. 
    (ZDI-11-174 / CVE-2011-1701)

  - The file-date-time parameter from the user specified
    printer-url is not properly handled before passing it to
    a fixed-length buffer on the heap. 
    (ZDI-11-175 / CVE-2011-1702)

  - The driver-version parameter from the user specified
    printer-url is not properly handled before passing it to
    a fixed-length buffer on the heap. 
    (ZDI-11-176 / CVE-2011-1703)
  
  - The core-package parameter from the user specified
    printer-url is not properly handled before passing it to
    a fixed-length buffer on the heap. 
    (ZDI-11-177 / CVE-2011-1704)

  - The client-file-name parameter from the user specified
    printer-url is not properly handled before passing it to
    a fixed-length buffer on the heap. 
    (ZDI-11-178 / CVE-2011-1705)

  - The iprint-client-config-info parameter from the user 
    specified printer-url is not properly handled before 
    passing it to a fixed-length buffer on the heap. 
    (ZDI-11-179 / CVE-2011-1706)

  - The op-printer-list-all-jobs cookie parameter from the 
    user specified printer-url is not properly handled 
    before passing it to a fixed-length buffer on the heap. 
    (ZDI-11-180 / CVE-2011-1708)

  - The op-printer-list-all-jobs url parameter from the user 
    specified printer-url is not properly handled before 
    passing it to a fixed-length buffer on the heap. 
    (ZDI-11-181 / CVE-2011-1707)"
  );
  
  script_set_attribute(attribute:"see_also", value:"http://download.novell.com/Download?buildid=6_bNby38ERg~");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-172/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-173/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-174/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-175/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-176/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-177/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-178/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-179/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-180/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-181/");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/518266/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/518267/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/518269/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/518270/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/518271/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/518268/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/518272/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/518273/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/518274/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/518275/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to Novell iPrint Client 5.64 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/07");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:iprint");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");

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

fixed_version = "5.6.4.0";
fixed_version_ui = "5.64";

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
