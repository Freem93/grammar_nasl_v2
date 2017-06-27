#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99362);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/04/17 14:16:27 $");

  script_cve_id("CVE-2016-8747");
  script_bugtraq_id(96895);
  script_osvdb_id(153593);

  script_name(english:"Apache Tomcat 9.0.0.M11 < 9.0.0.M17 nextRequest Information Disclosure");
  script_summary(english:"Checks the Apache Tomcat version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Tomcat installed on the remote host is 9.0.0.M11
or later but prior to 9.0.0.M17. It is, therefore, affected by an
information disclosure vulnerability in the nextRequest() function in
Http11InputBuffer.java due to improper limits of a ByteBuffer being
set. An unauthenticated, remote attacker can exploit this to disclose
ByteBuffer data associated with a different request.

Note that Nessus has not attempted to exploit this issue but has
instead relied only on the application's self-reported version number.");
  # https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.0.M17
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d171616");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 9.0.0.M17 or later.

Note that the vulnerability was also fixed in version 9.0.0.M16;
however, this version was never publicly released.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
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
tomcat_check_version(fixed:"9.0.0.M16", fixed_display: "9.0.0.M17", min:"9.0.0.M11", severity:SECURITY_WARNING, granularity_regex:"^(9(\.0(\.0)?)?)$");
