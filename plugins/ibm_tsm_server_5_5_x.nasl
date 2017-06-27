#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77116);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/08/12 01:06:36 $");

  script_cve_id("CVE-2012-2190","CVE-2012-2191","CVE-2013-0169");
  script_bugtraq_id(54743,55185,57778);
  script_osvdb_id(84474,84918,89848);

  script_name(english:"IBM Tivoli Storage Manager Server 5.5.x Multiple Vulnerabilities");
  script_summary(english:"Checks the version of IBM TSM.");

  script_set_attribute(attribute:"synopsis", value:"The remote backup service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Tivoli Storage Manager installed on the remote host
is 5.5 running on Windows or AIX. It is, therefore, potentially
affected by multiple flaws in its bundled SSL library:

  - A flaw that could allow a remote attacker to cause a
    denial of service via a specially crafted 'ClientHello'
    message. (CVE-2012-2190).

  - A flaw that could allow a remote attacker to cause a
    denial of service via a specially crafted value in
    the TLS Record Layer. (CVE-2012-2191).

  - A flaw that could allow a remote attacker to perform a
    statistical timing attack known as 'Lucky Thirteen'.
    (CVE-2013-0169).");

  # http://www-01.ibm.com/support/docview.wss?uid=swg21672360
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d4a4639");
  # http://www-01.ibm.com/support/docview.wss?uid=swg21672362
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?004af981");
  # http://www-01.ibm.com/support/docview.wss?uid=swg21672363
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?9986de60");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_tivoli_storage_manager_server_gskit_session_id_vulnerability_cve_2012_2190?lang=en_us
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?074f2e87");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_tivoli_storage_manager_server_gskit_encrypted_record_length_vulnerability_cve_2012_2191?lang=en_u
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?756252bb");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_tivoli_storage_manager_server_gskit_lucky_13_vulnerability_cve_2013_0169?lang=en_us
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?b7623c06");

  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Tivoli Storage Manager 6.2.6.0, 6.3.4.200 or later or
disable SSL.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("ibm_tsm_detect.nasl");
  script_require_keys("installed_sw/IBM Tivoli Storage Manager");
  script_require_ports("Services/tsm-agent");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

port = get_service(svc:"tsm-agent",exit_on_fail:TRUE);
prod = "IBM Tivoli Storage Manager";
get_install_count(app_name:prod, exit_if_zero:TRUE);
install = get_single_install(app_name:prod, port:port);

# Install data
os      = install["ReportedOS"]; # In very old versions this can be null
version = install["version"];

# We only care about 5.5 specifically
if(version !~ "^5\.5(\.|$)") audit(AUDIT_NOT_LISTEN, prod+" 5.5", port);

# See if SSL is on for the port we're checking
sslon = get_kb_item("Transports/TCP/"+port);
sslon = (sslon && sslon > ENCAPS_IP);

# If we cant determine the OS and we don't have paranoia on we don't continue
# this is probably a version so old it doesn't matter for these checks anyway
if(isnull(os) && report_paranoia < 2) exit(1,"Cannot determine operating system type");

# Work around is to turn SSL off
if(!sslon && report_paranoia < 2) audit(AUDIT_LISTEN_NOT_VULN, prod, port);

# Only Windows and AIX are affected.
if("Windows" >!< os  && "AIX" >!< os) audit(AUDIT_LISTEN_NOT_VULN, prod, port);

if(report_verbosity > 0)
{
  report =
    '\n  Port              : ' + port +
    '\n  Product           : ' + prod +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 6.2.6.0 / 6.3.4.200' +
    '\n';
    security_warning(port:port,extra:report);
} else security_warning(port);

