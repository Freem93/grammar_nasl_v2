#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56042);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/12 14:46:30 $");

  script_cve_id("CVE-2011-3388", "CVE-2011-3389");
  script_bugtraq_id(49388, 49978);
  script_osvdb_id(74828, 74829);
  script_xref(name:"CERT", value:"864643");

  script_name(english:"Opera < 11.51 Multiple Vulnerabilities (BEAST)");
  script_summary(english:"Checks version number of Opera.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote Windows host is prior to
11.51. It is, therefore, affected by multiple vulnerabilities :

  - An unspecified error can allow an insecure or malicious
    site to cause the browser to display security
    information belonging to another, secure site in the
    address bar. This causes the insecure or malicious site
    to appear to be part of, or secured by, a third-party
    site. (CVE-2011-3388)

  - An information disclosure vulnerability, known as BEAST,
    exists in the SSL 3.0 and TLS 1.0 protocols due to a
    flaw in the way the initialization vector (IV) is
    selected when operating in cipher-block chaining (CBC)
    modes. A man-in-the-middle attacker can exploit this
    to obtain plaintext HTTP header data, by using a
    blockwise chosen-boundary attack (BCBA) on an HTTPS
    session, in conjunction with JavaScript code that uses
    the HTML5 WebSocket API, the Java URLConnection API,
    or the Silverlight WebClient API. (CVE-2011-3389)");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1000/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/1151/");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2011/09/23/chromeandbeast.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/tls-cbc.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to Opera 11.51 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/01");
  
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Opera/Version");
version_ui = get_kb_item("SMB/Opera/Version_UI");

if (isnull(version_ui)) version_report = version;
else version_report = version_ui; 

fixed_version = "11.51.1087.0";

# Check if we need to display full version info in case of Alpha/Beta/RC
major_minor = eregmatch(string:version, pattern:"^([0-9]+\.[0-9]+)");
if (major_minor[1] == "11.51")
{
  fixed_version_report = fixed_version;
  version_report = version;
}
else
  fixed_version_report = "11.51";

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  if (report_verbosity > 0)
  {
    install_path = get_kb_item("SMB/Opera/Path");

    report = 
      '\n  Path              : ' + install_path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : ' + fixed_version_report +
      '\n';
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(port:get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, "The host is not affected since Opera "+version_report+" is installed.");
