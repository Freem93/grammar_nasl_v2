#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2014 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
# 
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(69096);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/05/22 11:11:55 $");

  script_name(english:"FreeBSD : phpMyAdmin -- multiple vulnerabilities (f4a0212f-f797-11e2-9bb9-6805ca0b3d42)");
  script_summary(english:"Checks for updated packages in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote FreeBSD host is missing one or more security-related
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The phpMyAdmin development team reports :

XSS due to unescaped HTML Output when executing a SQL query.

Using a crafted SQL query, it was possible to produce an XSS on the
SQL query form.

This vulnerability can be triggered only by someone who logged in to
phpMyAdmin, as the usual token protection prevents non-logged-in users
from accessing the required form.

5 XSS vulnerabilities in setup, chart display, process list, and logo
link.

- In the setup/index.php, using a crafted # hash with a JavaScript
event, untrusted JS code could be executed.

- In the Display chart view, a chart title containing HTML code was
rendered unescaped, leading to possible JavaScript code execution via
events.

- A malicious user with permission to create databases or users having
HTML tags in their name, could trigger an XSS vulnerability by issuing
a sleep query with a long delay. In the server status monitor, the
query parameters were shown unescaped.

- By configuring a malicious URL for the phpMyAdmin logo link in the
navigation sidebar, untrusted script code could be executed when a
user clicked the logo.

- The setup field for 'List of trusted proxies for IP allow/deny' Ajax
validation code returned the unescaped input on errors, leading to
possible JavaScript execution by entering arbitrary HTML.

If a crafted version.json would be presented, an XSS could be
introduced.

Due to not properly validating the version.json file, which is fetched
from the phpMyAdmin.net website, could lead to an XSS attack, if a
crafted version.json file would be presented.

This vulnerability can only be exploited with a combination of
complicated techniques and tricking the user to visit a page.

Full path disclosure vulnerabilities.

By calling some scripts that are part of phpMyAdmin in an unexpected
way, it is possible to trigger phpMyAdmin to display a PHP error
message which contains the full path of the directory where phpMyAdmin
is installed.

This path disclosure is possible on servers where the recommended
setting of the PHP configuration directive display_errors is set to
on, which is against the recommendations given in the PHP manual.

XSS vulnerability when a text to link transformation is used.

When the TextLinkTransformationPlugin is used to create a link to an
object when displaying the contents of a table, the object name is not
properly escaped, which could lead to an XSS, if the object name has a
crafted value.

The stored XSS vulnerabilities can be triggered only by someone who
logged in to phpMyAdmin, as the usual token protection prevents
non-logged-in users from accessing the required forms.

Self-XSS due to unescaped HTML output in schema export.

When calling schema_export.php with crafted parameters, it is possible
to trigger an XSS.

This vulnerability can be triggered only by someone who logged in to
phpMyAdmin, as the usual token protection prevents non-logged-in users
from accessing the required form.

SQL injection vulnerabilities, producing a privilege escalation
(control user).

Due to a missing validation of parameters passed to schema_export.php
and pmd_pdf.php, it was possible to inject SQL statements that would
run with the privileges of the control user. This gives read and write
access to the tables of the configuration storage database, and if the
control user has the necessary privileges, read access to some tables
of the mysql database.

These vulnerabilities can be triggered only by someone who logged in
to phpMyAdmin, as the usual token protection prevents non-logged-in
users from accessing the required form. Moreover, a control user must
have been created and configured as part of the phpMyAdmin
configuration storage installation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2013-8.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2013-9.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2013-11.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2013-12.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2013-13.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2013-14.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2013-15.php"
  );
  # http://sourceforge.net/projects/phpmyadmin/files/phpMyAdmin/3.5.8.2/phpMyAdmin-3.5.8.2-notes.html/view
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4c62957f"
  );
  # http://sourceforge.net/projects/phpmyadmin/files/phpMyAdmin/4.0.4.2/phpMyAdmin-4.0.4.2-notes.html/view
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8033f4e5"
  );
  # http://www.freebsd.org/ports/portaudit/f4a0212f-f797-11e2-9bb9-6805ca0b3d42.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?55337292"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phpMyAdmin35");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin>=4.0<4.0.4.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin35>=3.5<3.5.8.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
