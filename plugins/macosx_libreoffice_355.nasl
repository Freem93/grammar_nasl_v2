#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(61433);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/09/02 15:06:43 $");

  script_cve_id("CVE-2012-2665");
  script_bugtraq_id(54769);
  script_osvdb_id(84440, 84441, 84442);

  script_name(english:"LibreOffice < 3.5.5 Multiple Heap-Based Buffer Overflows (Mac OS X)");
  script_summary(english:"Checks version of LibreOffice");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains an application that is affected by multiple
buffer overflow vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A version of LibreOffice prior to 3.5.5 is installed on the remote
Mac OS X host.  It is, therefore, reportedly affected by multiple
heap-based buffer overflow vulnerabilities related to XML manifest
handling :

  - An error exists related to handling the XML tag
    hierarchy.

  - A boundary error exists when handling the duplication
    of certain unspecified XML tags.

  - An error exists in the base64 decoder related to XML
    export actions."
  );
  # http://blog.documentfoundation.org/2012/07/11/libreoffice-3-5-5-is-available/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc6741ee");
  script_set_attribute(attribute:"see_also", value:"http://www.libreoffice.org/advisories/CVE-2012-2665/");
  script_set_attribute(attribute:"solution", value:"Upgrade to LibreOffice version 3.5.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
  script_dependencies("macosx_libreoffice_installed.nasl");
  script_require_keys("MacOSX/LibreOffice/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = "MacOSX/LibreOffice";
get_kb_item_or_exit(kb_base+"/Installed");
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);
version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  # nb: first release of LibreOffice was 3.3.0.
  ver[0] == 3 &&
  (
    ver[1] < 5 ||
    (ver[1] == 5 && ver[2] < 5)  # < 3.5.5
  )
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path + 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : 3.5.5\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "LibreOffice", version, path);
