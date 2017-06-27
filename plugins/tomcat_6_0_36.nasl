#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62987);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/19 18:02:20 $");

  script_cve_id(
    "CVE-2012-2733",
    "CVE-2012-3546",
    "CVE-2012-4431",
    "CVE-2012-4534",
    "CVE-2012-5885",
    "CVE-2012-5886",
    "CVE-2012-5887"
  );
  script_bugtraq_id(56402, 56403, 56812, 56813, 56814);
  script_osvdb_id(87223, 87227, 87579, 87580, 88093, 88094, 88095);

  script_name(english:"Apache Tomcat 6.0.x < 6.0.36 Multiple Vulnerabilities");
  script_summary(english:"Checks the Apache Tomcat version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 6.0 listening on the remote host is prior to Tomcat 6.0.36. It
is, therefore, affected by multiple vulnerabilities :

  - A flaw exists within the parseHeaders() function that
    allows for a crafted header to cause a remote denial of
    service. (CVE-2012-2733)

  - An error exists related to FORM authentication that
    allows a security bypass if 'j_security_check' is
    appended to the request. (CVE-2012-3546)

  - An error exists in the file
    'filters/CsrfPreventionFilter.java' that allows
    cross-site request forgery (XSRF) attacks to bypass
    the filtering. This can allow access to protected
    resources without a session identifier. (CVE-2012-4431)

  - An error exists related to the 'NIO' connector when
    HTTPS and 'sendfile' are enabled that can force the
    application into an infinite loop. (CVE-2012-4534)

  - Replay-countermeasure functionality in HTTP Digest
    Access Authentication tracks cnonce values instead of
    nonce values, which makes it easier for attackers to
    bypass access restrictions by sniffing the network for
    valid requests. (CVE-2012-5885)

  - The HTTP Digest Access Authentication implementation
    caches information about the authenticated user, which
    allows an attacker to bypass authentication via session
    ID. (CVE-2012-5886)

  - The HTTP Digest Access Authentication implementation
    does not properly check for stale nonce values with
    enforcement of proper credentials, which allows an
    attacker to bypass restrictions by sniffing requests.
    (CVE-2012-5887)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.36");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Dec/72");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Dec/73");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Dec/74");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache Tomcat version 6.0.36 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("tomcat_error_version.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/tomcat");

  exit(0);
}

include("tomcat_version.inc");

tomcat_check_version(fixed:"6.0.36", min:"6.0.0", severity:SECURITY_WARNING, xsrf:TRUE, granularity_regex:"^6(\.0)?$");
