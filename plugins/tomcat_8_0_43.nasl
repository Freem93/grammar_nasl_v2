#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99367);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/04/15 13:47:38 $");

  script_cve_id("CVE-2017-5647");
  script_bugtraq_id(97529);
  script_osvdb_id(155234);
  script_xref(name:"IAVB", value:"2017-B-0044");

  script_name(english:"Apache Tomcat 6.0.x < 6.0.53 / 7.0.x < 7.0.77 / 8.0.x < 8.0.43 Pipelined Requests Information Disclosure");
  script_summary(english:"Checks the Apache Tomcat version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Apache Tomcat
service running on the remote host is 6.0.x prior to 6.0.53, 7.0.x
prior to 7.0.77, or 8.0.x prior to 8.0.43. It is therefore, affected
by a flaw in the handling of pipelined requests when send file
processing is used that results in the pipelined request being lost
when processing of the previous request has completed, causing
responses to be sent for the wrong request. An unauthenticated, remote
attacker can exploit this to disclose sensitive information.

Note that Nessus has not attempted to exploit this issue but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.53");
  script_set_attribute(attribute:"see_also", value:"https://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.77");
  script_set_attribute(attribute:"see_also", value:"https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.0.43");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 6.0.53 / 7.0.77 / 8.0.43 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("tomcat_error_version.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/tomcat");

  exit(0);
}

include("tomcat_version.inc");
tomcat_check_version(fixed:make_list("6.0.53", "7.0.77", "8.0.43"), severity:SECURITY_WARNING, granularity_regex:"^(6(\.0)?|7(\.0)?|8(\.0)?)$");
