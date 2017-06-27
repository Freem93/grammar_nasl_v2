#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94578);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/05 16:04:17 $");

  script_cve_id(
    "CVE-2016-0762",
    "CVE-2016-5018",
    "CVE-2016-6794",
    "CVE-2016-6796",
    "CVE-2016-6797"
  );
  script_bugtraq_id(
    93939,
    93940,
    93942,
    93943,
    93944
  );
  script_osvdb_id(
    146348,
    146354,
    146355,
    146356,
    146357
  );

  script_name(english:"Apache Tomcat 6.0.x < 6.0.47 / 7.0.x < 7.0.72 / 8.0.x < 8.0.37 / 8.5.x < 8.5.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the Apache Tomcat version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Apache Tomcat
service running on the remote host is 6.0.x prior to 6.0.47, 7.0.x
prior to 7.0.72, 8.0.x prior to 8.0.37, or 8.5.x prior to 8.5.5. It
is, therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists due to a
    failure to process passwords when paired with a
    non-existent username. An unauthenticated, remote
    attacker can exploit this, via a timing attack, to
    enumerate user account names. (CVE-2016-0762)

  - A security bypass vulnerability exists that allows a
    local attacker to bypass a configured SecurityManager
    via a utility method that is accessible to web
    applications. (CVE-2016-5018)

  - An information disclosure vulnerability exists in the
    SecurityManager component due to a failure to properly
    restrict access to system properties for the
    configuration files system property replacement feature.
    An attacker can exploit this, via a specially crafted
    web application, to bypass SecurityManager restrictions
    and disclose system properties. (CVE-2016-6794)

  - A security bypass vulnerability exists that allows a
    local attacker to bypass a configured SecurityManager by
    changing the configuration parameters for a JSP servlet.
    (CVE-2016-6796)

  - A security bypass vulnerability exists due to a failure
    to limit web application access to global JNDI
    resources. A local attacker can exploit this to gain
    unauthorized access to resources. (CVE-2016-6797)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  # https://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.47
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c3fa418");
  # https://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.72
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be50738a");
  # https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.5_and_8.0.37
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?47795ca8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 6.0.47 / 7.0.72 / 8.0.37 / 8.5.5 or
later. Note that versions 6.0.46 and 7.0.71 also resolve the
vulnerabilities; however, these versions were never officially
released by the vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("tomcat_error_version.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/tomcat");

  exit(0);
}

include("tomcat_version.inc");
tomcat_check_version(fixed:make_list("6.0.47", "7.0.72", "8.0.37", "8.5.5"), severity:SECURITY_WARNING);
