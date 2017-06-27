#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51059);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/23 20:42:24 $");

  script_cve_id(
    "CVE-2007-2449",
    "CVE-2007-2450",
    "CVE-2007-3382",
    "CVE-2007-3385",
    "CVE-2007-3386"
  );
  script_bugtraq_id(24475, 24476, 25314, 25316);
  script_osvdb_id(36079, 36080, 36417, 37070, 37071);
  script_xref(name:"CERT", value:"993544");
  script_xref(name:"Secunia", value:"25678");
  script_xref(name:"Secunia", value:"26465");
  script_xref(name:"Secunia", value:"26466");

  script_name(english:"Apache Tomcat 5.0.x <= 5.0.30 / 5.5.x < 5.5.25 Multiple Vulnerabilities");
  script_summary(english:"Checks the Apache Tomcat version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance Apache
Tomcat running on the remote host is 5.0.x equal to or prior to 5.0.30
or 5.5.x prior to 5.5.25. It is, therefore, affected by multiple
vulnerabilities :

  - An error exists in several JSP example files that allows
    script injection via URLs using the ';' character.
    (CVE-2007-2449)

  - The Manager and Host Manager applications do not
    properly sanitize the 'filename' parameter of the
    '/manager/html/upload' script, which can lead to cross-
    site scripting attacks. (CVE-2007-2450)

  - An error exists in the handling of cookie values
    containing single quotes which Tomcat treats as
    delimiters. This can allow disclosure of sensitive
    information such as session IDs. (CVE-2007-3382)

  - An error exists in the handling of cookie values
    containing backslashes which Tomcat treats as
    delimiters. This can allow disclosure of sensitive
    information such as session IDs. (CVE-2007-3385)

  - An error exists in the Host Manager application which
    allows script injection. (CVE-2007-3386)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://tomcat.apache.org/security-5.html#Fixed_in_Apache_Tomcat_5.5.25,_5.0.SVN
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1a40289c");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Jun/180");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Jun/182");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 5.5.25. Alternatively, use the latest
SVN source for 5.0.x. The 5.0.x branch was fixed in SVN revision
number 588821.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("tomcat_error_version.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/tomcat");

  exit(0);
}

include("tomcat_version.inc");

# nb: 5.0.30 was the last 5.0.x and thus all 5.0.x are vuln
tomcat_check_version(fixed:"5.5.25", min:"5.0.0", severity:SECURITY_WARNING, xss:TRUE, granularity_regex:"^5(\.5)?$");
