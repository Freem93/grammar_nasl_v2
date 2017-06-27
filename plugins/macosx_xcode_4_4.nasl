#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61413);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/16 14:02:53 $");

  script_cve_id("CVE-2011-3389", "CVE-2012-3698");
  script_bugtraq_id(49778, 54679);
  script_osvdb_id(74829, 84227);
  script_xref(name:"CERT", value:"864643");

  script_name(english:"Apple Xcode < 4.4 Multiple Vulnerabilities (Mac OS X) (BEAST)");
  script_summary(english:"Checks version of Xcode.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an application installed that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X host has a version of Apple Xcode installed that
is prior to 4.4. It is, therefore, affected by multiple
vulnerabilities :

  - An information disclosure vulnerability, known as BEAST,
    exists in the SSL 3.0 and TLS 1.0 protocols due to a
    flaw in the way the initialization vector (IV) is
    selected when operating in cipher-block chaining (CBC)
    modes. A man-in-the-middle attacker can exploit this
    to obtain plaintext HTTP header data, by using a
    blockwise chosen-boundary attack (BCBA) on an HTTPS
    session, in conjunction with JavaScript code that uses
    the HTML5 WebSocket API, the Java URLConnection API,
    or the Silverlight WebClient API. (CVE-2011-3389)

  - An information disclosure vulnerability exists that may 
    allow a specially crafted App Store application to read 
    entries in the keychain. (CVE-2012-3698)"
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5416");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Jul/msg00001.html");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2011/09/23/chromeandbeast.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/tls-cbc.txt");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Apple Xcode version 4.4 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:xcode");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies('macosx_xcode_installed.nasl');
  script_require_keys('MacOSX/Xcode/Installed');
  
  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');

kb_base = "MacOSX/Xcode/";
appname = 'Apple Xcode';
report = '';

num_installed = get_kb_item_or_exit(kb_base+'NumInstalled');

for (install_num = 0; install_num < num_installed; install_num++)
{
  path = get_kb_item_or_exit(kb_base+install_num+'/Path');
  ver = get_kb_item_or_exit(kb_base+install_num+'/Version');
  fix = '4.4';
  
  if (ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
  {
      report += 
        '\n  Path              : ' + path +
        '\n  Installed version : ' + ver +
        '\n  Fixed version     : ' + fix + '\n';
  }
}

if (report)
{
  if (report_verbosity > 0) security_warning(port:0, extra:report);
  else security_warning(0);

  exit(0);
} 
else exit(0, 'No affected ' +  appname + ' installs were found.');
