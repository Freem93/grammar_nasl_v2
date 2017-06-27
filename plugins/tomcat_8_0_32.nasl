#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88937);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/30 23:05:17 $");

  script_cve_id(
    "CVE-2015-5346",
    "CVE-2015-5351",
    "CVE-2016-0706",
    "CVE-2016-0714",
    "CVE-2016-0763"
  );
  script_bugtraq_id(
    83323,
    83324,
    83326,
    83327,
    83330
  );
  script_osvdb_id(
    134824,
    134825,
    134827,
    134828,
    134829
  );

  script_name(english:"Apache Tomcat 8.0.0.RC1 < 8.0.32 Multiple Vulnerabilities");
  script_summary(english:"Checks the Apache Tomcat version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Apache Tomcat
service running on the remote host is 8.0.x prior to 8.0.32. It is,
therefore, affected by multiple vulnerabilities :

  - A flaw exists due to a failure to invalidate a previous
    session ID when assigning an ID to a new session. An
    attacker can exploit this, via a crafted request that
    uses the requestedSessionSSL field to fixate the session
    ID, to ensure that the user authenticates with a known
    session ID, allowing the session to be subsequently
    hijacked. (CVE-2015-5346)

  - An information disclosure vulnerability exists in the
    Manager and Host Manager web applications due to a flaw
    in the index page when issuing redirects in response to
    unauthenticated requests for the root directory of the
    application. An unauthenticated, remote attacker can
    exploit this to gain access to the XSRF token
    information stored in the index page. (CVE-2015-5351)

  - An information disclosure vulnerability exists that
    allows a specially crafted web application to load the
    StatusManagerServlet. An attacker can exploit this to
    gain unauthorized access to a list of all deployed
    applications and a list of the HTTP request lines for
    all requests currently being processed. (CVE-2016-0706)

  - A security bypass vulnerability exists due to a flaw
    in the StandardManager, PersistentManager, and cluster
    implementations that is triggered when handling
    persistent sessions. An unauthenticated, remote attacker
    can exploit this, via a crafted object in a session, to
    bypass the security manager and execute arbitrary code.
    (CVE-2016-0714)

  - A flaw exists due to the setGlobalContext() method of
    ResourceLinkFactory being accessible to web applications
    even when run under a security manager. An
    unauthenticated, remote attacker can exploit this to
    inject malicious global context, allowing data owned by
    other web applications to be read or written to.
    (CVE-2016-0763)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  # http://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.0.32
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6906ceb2");
  script_set_attribute(attribute:"solution", value:
"Although version 8.0.31 fixes these issues, that version was not
officially released, and the vendor recommends upgrading to 8.0.32 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("tomcat_error_version.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/tomcat");

  exit(0);
}

include("tomcat_version.inc");
tomcat_check_version(fixed:"8.0.32", min:"8.0.0", severity:SECURITY_HOLE, granularity_regex:"^8(\.0)?$");
