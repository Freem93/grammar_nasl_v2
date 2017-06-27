#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95438);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/06 16:27:35 $");

  script_cve_id(
    "CVE-2016-6816",
    "CVE-2016-6817",
    "CVE-2016-8735"
  );
  script_bugtraq_id(
    94097,
    94461,
    94463
  );
  script_osvdb_id(
    147617,
    147618,
    147619
  );

  script_name(english:"Apache Tomcat 6.0.x < 6.0.48 / 7.0.x < 7.0.73 / 8.0.x < 8.0.39 / 8.5.x < 8.5.8 Multiple Vulnerabilities");
  script_summary(english:"Checks the Apache Tomcat version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Apache Tomcat
service running on the remote host is 6.0.x prior to 6.0.48, 7.0.x
prior to 7.0.73, 8.0.x prior to 8.0.39, or 8.5.x prior to 8.5.8. It
is, therefore, affected by multiple vulnerabilities :

  - A flaw exists that is triggered when handling request
    lines containing certain invalid characters. An 
    unauthenticated, remote attacker can exploit this, by
    injecting additional headers into responses, to conduct
    HTTP response splitting attacks. (CVE-2016-6816)

  - A denial of service vulnerability exists in the HTTP/2
    parser due to an infinite loop caused by improper
    parsing of overly large headers. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted request, to cause a denial of service condition.
    Note that this vulnerability only affects 8.5.x
    versions. (CVE-2016-6817)

  - A remote code execution vulnerability exists in the JMX
    listener in JmxRemoteLifecycleListener.java due to
    improper deserialization of Java objects. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2016-8735)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  # https://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.48
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e8a81e1");
  # https://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.73
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c7e7b23");
  # https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.0.39
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?833cb56a");
  # https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87d6ed56");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 6.0.48 / 7.0.73 / 8.0.39 / 8.5.8 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/01");

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
tomcat_check_version(fixed:make_list("6.0.48", "7.0.73", "8.0.39", "8.5.8"), severity:SECURITY_HOLE, granularity_regex:"^(6(\.0)?|7(\.0)?|8(\.(0|5))?)$");
