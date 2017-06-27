#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56008);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/09 20:31:00 $");

  script_cve_id(
    "CVE-2011-1184",
    "CVE-2011-2204",
    "CVE-2011-2526",
    "CVE-2011-2729",
    "CVE-2011-5062",
    "CVE-2011-5063",
    "CVE-2011-5064"
  );
  script_bugtraq_id(48456, 48667, 49143, 49762);
  script_osvdb_id(73429, 73797, 73798, 74541, 76189, 78598, 78599, 78600);

  script_name(english:"Apache Tomcat 6.0.x < 6.0.33 Multiple Vulnerabilities");
  script_summary(english:"Checks the Apache Tomcat version.");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 6.0.x listening on the remote host is prior to 6.0.33. It is,
therefore, affected by multiple vulnerabilities :

  - Several weaknesses were found in the HTTP Digest
    authentication implementation. The issues are as
    follows: replay attacks are possible, server nonces
    are not checked, client nonce counts are not checked,
    'quality of protection' (qop) values are not checked,
    realm values are not checked and the server secret is
    a hard-coded, known string. The effect of these issues
    is that Digest authentication is no stronger than Basic
    authentication. (CVE-2011-1184, CVE-2011-5062,
    CVE-2011-5063, CVE-2011-5064)

  - An error handling issue exists related to the
    MemoryUserDatabase that allows user passwords to be
    disclosed through log files. (CVE-2011-2204)

  - An input validation error exists that allows a local
    attacker to either bypass security or carry out denial
    of service attacks when the APR or NIO connectors are
    enabled. (CVE-2011-2526)

  - A component that Apache Tomcat relies on called 'jsvc'
    contains an error in that it does not drop capabilities
    after starting and can allow access to sensitive files
    owned by the super user. Note this vulnerability only
    affects Linux operating systems and only when the
    following are true: jsvc is compiled with libpcap and
    the '-user' parameter is used. (CVE-2011-2729)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.33");
  # http://mail-archives.apache.org/mod_mbox/tomcat-announce/201108.mbox/%3C20110818135645.GA98251@minotaur.apache.org%3E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b56cc2cd");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache Tomcat version 6.0.33 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("tomcat_error_version.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/tomcat");

  exit(0);
}

include("tomcat_version.inc");

tomcat_check_version(fixed:"6.0.33", min:"6.0.0", severity:SECURITY_WARNING, granularity_regex:"^6(\.0)?$");
