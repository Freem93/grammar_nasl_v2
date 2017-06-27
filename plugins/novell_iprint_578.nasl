#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57890);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2012/08/30 14:45:18 $");

  script_cve_id("CVE-2011-4185", "CVE-2011-4186", "CVE-2011-4187");
  script_bugtraq_id(51926);
  script_osvdb_id(78953, 78954, 78955);

  script_name(english:"Novell iPrint Client < 5.78 Multiple Code Execution Vulnerabilities");
  script_summary(english:"Checks version of Novell iPrint Client");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains an application that is affected by multiple
code execution vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Novell iPrint Client installed on the remote host is
earlier than 5.78.  Such versions are reportedly affected by one or
more of the following vulnerabilities that can allow for arbitrary
code execution :

  - An unspecified issue exists in the GetDriverSettings 
    realm in nipplib.dll. (CVE-2011-4187)

  - An unspecified issue exists in GetPrinterURLList2 in the 
    ActiveX control. (CVE-2011-4185)

  - An unspecified issue exists in client-file-name parsing 
    in nipplib.dll. (CVE-2011-4186)");

  script_set_attribute(attribute:"see_also", value:"http://dvlabs.tippingpoint.com/advisory/TPTI-12-02");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-12-102/");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-12-181/");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/524037/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/viewContent.do?externalId=7008708");
  script_set_attribute(attribute:"solution", value:"Upgrade to Novell iPrint Client 5.78 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:iprint");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("novell_iprint_532.nasl");
  script_require_keys("SMB/Novell/iPrint/Version", "SMB/Novell/iPrint/Version_UI");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

kb_base = "SMB/Novell/iPrint/";

version = get_kb_item_or_exit(kb_base+"Version");
version_ui = get_kb_item_or_exit(kb_base+"Version_UI");
dll = get_kb_item_or_exit(kb_base+"DLL");

fixed_version = "5.7.8.0";
fixed_version_ui = "5.78";

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
else exit(0, "The Novell iPrint Client "+version_ui+" install on the host is not affected.");
