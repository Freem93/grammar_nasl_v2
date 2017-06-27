#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62988);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/09 20:31:00 $");

  script_cve_id(
    "CVE-2012-3544",
    "CVE-2012-3546",
    "CVE-2012-5885",
    "CVE-2012-5886",
    "CVE-2012-5887"
  );
  script_bugtraq_id(56403, 56812, 59797);
  script_osvdb_id(87223, 87579, 87580, 88094, 93253);

  script_name(english:"Apache Tomcat 7.0.x < 7.0.30 Multiple Vulnerabilities");
  script_summary(english:"Checks the Apache Tomcat version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 7.0 listening on the remote host is prior to 7.0.30. It is,
therefore, affected by the following vulnerabilities :

  - An error related to chunked transfer encoding and
    extensions allows limited denial of service attacks.
    (CVE-2012-3544)

  - An error exists related to FORM authentication that
    allows security bypass if 'j_security_check' is appended
    to the request. (CVE-2012-3546)

  - Replay-countermeasure functionality in HTTP Digest
    Access Authentication tracks cnonce values instead of
    nonce values, which makes it easier for attackers to
    bypass access restrictions by sniffing the network for
    valid requests. (CVE-2012-5885)

  - HTTP Digest Access Authentication implementation caches
    information about the authenticated user, which allows
    an attacker to bypass authentication via session ID.
    (CVE-2012-5886)

  - HTTP Digest Access Authentication implementation does
    not properly check for stale nonce values with
    enforcement of proper credentials, which allows an
    attacker to bypass restrictions by sniffing requests.
    (CVE-2012-5887)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.30");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Dec/73");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache Tomcat version 7.0.30 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/04");
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

tomcat_check_version(fixed:"7.0.30", min:"7.0.0", severity:SECURITY_WARNING, xsrf:TRUE, granularity_regex:"^7(\.0)?$");
