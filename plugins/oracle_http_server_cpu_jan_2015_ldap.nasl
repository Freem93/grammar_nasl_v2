#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81003);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/07 18:00:12 $");

  script_cve_id("CVE-2011-3389");
  script_bugtraq_id(49778);
  script_osvdb_id(74829);
  script_xref(name:"CERT", value:"864643");

  script_name(english:"Oracle Fusion Middleware Security Service Information Disclosure (January 2015 CPU) (BEAST)");
  script_summary(english:"Checks the version of Oracle HTTP Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle HTTP Server installed on the remote host is
affected by an information disclosure vulnerability, known as BEAST,
in the SSL 3.0 and TLS 1.0 protocols due to a flaw in the way the
initialization vector (IV) is selected when operating in cipher-block
chaining (CBC) modes. A man-in-the-middle attacker can exploit this to
obtain plaintext HTTP header data, by using a blockwise
chosen-boundary attack (BCBA) on an HTTPS session, in conjunction with
JavaScript code that uses the HTML5 WebSocket API, the Java
URLConnection API, or the Silverlight WebClient API.");
  # http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c02f1515");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2011/09/23/chromeandbeast.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/tls-cbc.txt");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2015 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:http_server");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("oracle_http_server_installed.nbin");
  script_require_keys("Oracle/OHS/Installed");

  exit(0);
}

include("global_settings.inc");
include("oracle_rdbms_cpu_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("Oracle/OHS/Installed");
installs = get_kb_list_or_exit("Oracle/OHS/*/Version");
hascomp  = FALSE;

# For this check, we need Middleware home which should be
# oracle_common one directory up
foreach install (keys(installs))
{
  mwohome = install - 'Oracle/OHS/';
  mwohome = mwohome - '/Version';

  mwohome = ereg_replace(pattern:'^(/.*/).*$', string:mwohome, replace:"\1oracle_common");

  # Make sure the component that is being patched exists in
  # the Middleware home
  if (find_oracle_component_in_ohome(ohome:mwohome, compid:'oracle.ldap.rsf'))
  {
    hascomp = TRUE;
    mwinstalls[mwohome] = installs[install];
  }
}

patches = make_array();
patches['12.1.3.0'] = make_list('19485414');
patches['12.1.2.0'] = make_list('19485397');

if(hascomp)
{
  oracle_product_check_vuln(
    product   : 'Oracle HTTP Server',
    installs  : mwinstalls,
    patches   : patches
  );
}
else exit(0, 'No Middleware Homes were found with the oracle.ldap.rsf component.');
