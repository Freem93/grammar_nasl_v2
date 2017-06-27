#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53323);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/09 20:31:00 $");

  script_cve_id(
    "CVE-2011-1183",
    "CVE-2011-1184",
    "CVE-2011-1475",
    "CVE-2011-5062",
    "CVE-2011-5063",
    "CVE-2011-5064"
  );
  script_bugtraq_id(47196, 47199, 49762);
  script_osvdb_id(71027, 73776, 76189, 78598, 78599, 78600);
  script_xref(name:"Secunia", value:"43684");

  script_name(english:"Apache Tomcat 7.x < 7.0.12 Multiple Vulnerabilities");
  script_summary(english:"Checks the Apache Tomcat version.");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 7.x listening on the remote host is prior to 7.0.12. It is,
therefore, affected by multiple vulnerabilities :

  - A fix for CVE-2011-1088 introduced a security bypass
    vulnerability. If login configuration data is absent
    from the 'web.xml' file and a web application is
    marked as 'metadata-complete', security constraints are
    ignored and may be bypassed by an attacker. Please note
    this vulnerability only affects version 7.0.11 of
    Tomcat. (CVE-2011-1183)

  - Several weaknesses were found in the HTTP Digest
    authentication implementation. The issues are as
    follows: replay attacks are possible, server nonces
    are not checked, client nonce counts are not checked,
    'quality of protection' (qop) values are not checked,
    realm values are not checked, and the server secret is
    a hard-coded, known string. The effect of these issues
    is that Digest authentication is no stronger than Basic
    authentication. (CVE-2011-1184, CVE-2011-5062,
    CVE-2011-5063, CVE-2011-5064)

  - Updates to the HTTP BIO connector, in support of
    Servlet 3.0 asynchronous requests, fail to completely
    handle HTTP pipelining. Sensitive information may be
    disclosed because responses from the server can be
    improperly returned to the wrong request and possibly
    to the wrong user. (CVE-2011-1475)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?343187a6");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/bugzilla/show_bug.cgi?id=50928");
  script_set_attribute(attribute:"see_also", value:"http://svn.apache.org/viewvc?view=revision&revision=1087643");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache Tomcat version 7.0.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/07");

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

tomcat_check_version(fixed:"7.0.12", min:"7.0.0", severity:SECURITY_WARNING, granularity_regex:"^7(\.0)?$");
