#TRUSTED 446b71ef07b6522c71a0c736278be3ab3fb41b60405ad55bab47f05b14103ab86875e85b98a9ffaf83509717c40ab348679b61708f3f2ee98e07b764fba81a96f62d139559bee213810e650915858fab473aaf68de617746ca7d4f91868fc59fd24ed0e6bbf8c4c2c1e6ed12e9c4f5b7a511adcc279404389ed5aff51e608ecf00152895e87025f8a123d278e5618c560824d17a524140776bbfae5bb89c5676418a583cf1c836628dcb97b5f016778bbd6aa1eb96eccf44b4b8ecd45933c2fc34173f3c014acb5dccbe9504d4f5552075a4493fb4a75f47d3faba2b8c2883c4ff0bc35ab187d52e4a4f6c45627a1d3f945c58086d6fd7b99dcb153d3a3dd7898c3898b9eb264837825e5661d641e1a4dec5e2049fb0f15b3193fe3c54fb05ebafd4eeeb049a2fcaed20ec4df1b28f6b4575e781ee858787d9f2d58d3fc9dff9b7fd47e0817afb64d2e428851c7d6c3b03aed883b36061939d42e118e45aa82732c2b92c68b16744888bc9c8eab262c1c2a265abd6987414b73cd1e106cca8b9b73c00b8e50c375b71474a81ff396c5b499b5b40fd47c503596e1ce21038ed742d99b0c743f117bceb061070c3ea44c45ecbf29f950504f97406a02beb49492b81558483c95add726ae467937ecd7bf2829210cd78202f6a97bb0d53c402b5f95949d759f1ead634d6316dd1011ba53d75aca2057c134019d57ccfc3fed5e0ea
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89963);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/03");

  script_cve_id("CVE-2015-8503");
  script_osvdb_id(132099);

  script_name(english:"Tenable SecurityCenter 5.0.2 Audit File XSS (TNS-2015-12)");
  script_summary(english:"Checks the SecurityCenter version.");

  script_set_attribute(attribute:"synopsis", value:
"The application installed on the remote host is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Tenable SecurityCenter application
installed on the remote host is affected by a cross-site scripting
(XSS) vulnerability due to improper validation of uploaded .audit
files before they are rendered on the scan results page. An
authenticated, remote attacker can exploit this, via a crafted .audit
file that is later viewed by an administrator, to execute arbitrary
code in the user's browser session.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.tenable.com/security/tns-2015-12");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable SecurityCenter version 5.2.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:L/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("securitycenter_installed.nbin");
  script_require_keys("Host/SecurityCenter/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/SecurityCenter/Version");

# Affects 5.0.2
if (version == "5.0.2")
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  report_items = make_array(
    "Installed version", version,
    "Fixed version", "5.2.0"
  );
  report = report_items_str(report_items:report_items);
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'SecurityCenter', version);
