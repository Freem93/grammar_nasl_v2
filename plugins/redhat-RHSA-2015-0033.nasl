#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0033. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80505);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/22 13:36:33 $");

  script_cve_id("CVE-2014-7811", "CVE-2014-7812");
  script_bugtraq_id(74825, 74829);
  script_osvdb_id(117027);
  script_xref(name:"RHSA", value:"2015:0033");

  script_name(english:"RHEL 6 : Satellite Server (RHSA-2015:0033)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Red Hat Satellite 5.7.0 is now available. Updated packages that fix
two security issues, several bugs, and add various enhancements are
now available for Red Hat Satellite 5.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Red Hat Satellite provides a solution to organizations requiring
absolute control over and privacy of the maintenance and package
deployment of their servers. It allows organizations to utilize the
benefits of Red Hat Network (RHN) without having to provide public
Internet access to their servers or other client systems.

This update introduces Red Hat Satellite 5.7.0. For the full list of
new features included in this release, see the Release Notes document
at :

https://access.redhat.com/documentation/en-US/Red_Hat_Satellite/5.7/

Note: Red Hat Satellite 5.7 and Red Hat Satellite Proxy 5.7 are
available for installation on Red Hat Enterprise Linux Server 6. For
full details, including supported architecture combinations, refer to
the Red Hat Satellite 5.7 Installation Guide.

This update fixes the following security issues :

Multiple stored cross-site scripting (XSS) flaw were found in the
handling of XML data passed to Satellite via the REST API. By sending
a specially crafted request to Satellite, a remote, authenticated
attacker could embed HTML content into the stored data, allowing them
to inject malicious content into the web page that is used to view
that data. (CVE-2014-7811)

A stored cross-site scripting (XSS) flaw was found in the System
Groups field. By sending a specially crafted request to Satellite, a
remote, authenticated attacker could embed HTML content into the
stored data, allowing them to inject malicious content into the web
page that is used to view that data. (CVE-2014-7812)

Red Hat would like to thank Mickael Gallier for reporting these
issues.

All users of Red Hat Satellite are advised to install this newly
released version."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-7811.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-7812.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/documentation/en-US/Red_Hat_Satellite/5.7/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-0033.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:MessageQueue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:NOCpulsePlugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:NOCpulsePlugins-Oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:NPalert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ProgAGoGo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:PyYAML");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:SNMPAlerts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:SatConfig-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:SatConfig-bootstrap-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:SatConfig-cluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:SatConfig-general");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:SatConfig-generator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:SatConfig-installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:SatConfig-spread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:SputLite-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:SputLite-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ace-editor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:antlr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-beanutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bootstrap-datepicker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:c3p0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cglib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cobbler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cobbler-loaders");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:concurrent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cx_Oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dojo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dom4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dwr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:editarea");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eventReceivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:font-awesome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jabberd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jabberpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-chain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-codec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-digester");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-fileupload");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-io");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-logging-jboss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-oro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-taglibs-standard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:javassist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-javaee-poms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-transaction-1.0.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jcommon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jdom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jfreechart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jpam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jquery-timepicker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jquery-ui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libapreq2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgsasl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libntlm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreadline-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:momentjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nocpulse-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nocpulse-db-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nutch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:objectweb-asm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:oracle-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:oracle-instantclient-basic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:oracle-instantclient-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:oracle-instantclient-sqlplus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:oracle-instantclient-sqlplus-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:oracle-nofcontext-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:osa-dispatcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:osa-dispatcher-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:oscache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:patternfly1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Apache-DBI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-BerkeleyDB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Cache-Cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Class-MethodMaker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Class-Singleton");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Config-IniFiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Convert-BinHex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Crypt-DES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Crypt-GeneratePassword");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-DBD-Oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-DateTime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Email-Date-Format");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Filesys-Df");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-HTML-TableExtract");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-IO-stringy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-IPC-ShareLite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-List-MoreUtils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-MIME-Lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-MIME-Types");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-MIME-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Mail-RFC822-Address");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-NOCpulse-CLAC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-NOCpulse-Debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-NOCpulse-Gritch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-NOCpulse-Object");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-NOCpulse-OracleDB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-NOCpulse-PersistentConnection");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-NOCpulse-Probe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-NOCpulse-Probe-Oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-NOCpulse-ProcessPool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-NOCpulse-Scheduler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-NOCpulse-SetID");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-NOCpulse-Utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Net-INET6Glue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Net-IPv4Addr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Net-SNMP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Params-Validate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-SOAP-Lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Satcon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-TermReadKey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-XML-Generator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-libapreq2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql92-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql92-postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql92-postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql92-postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql92-postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql92-postgresql-upgrade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql92-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pwstrength-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-debian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gzipstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-psycopg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:quartz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:quartz-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redstone-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhn-i18n-guides");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhn-i18n-release-notes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhn-solaris-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhn_solaris_bootstrap_5_4_1_9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhnlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhnpush");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:roboto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-doc-indexes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-repo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:scdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:scl-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:select2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:select2-bootstrap-css");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:simple-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sitemesh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacecmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-app");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-config-files");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-config-files-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-config-files-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-iss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-iss-export");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-package-push-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-sql-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-sql-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-xml-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-base-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-base-minimal-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-certs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-dobby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-grail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-monitoring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-monitoring-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-pxt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-reports");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-search");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-setup-jabberd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-setup-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-slf4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-sniglets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-ssl-cert-check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-taskomatic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ssl_bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:status_log_acceptor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:stringtree-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:struts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:struts-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:struts-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:struts-taglib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tanukiwrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tsdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:udns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xalan-j2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:0033";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;

  if (! (rpm_exists(release:"RHEL6", rpm:"spacewalk-admin-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Satellite Server");

  if (rpm_check(release:"RHEL6", reference:"MessageQueue-3.26.10-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"NOCpulsePlugins-2.209.7-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"NOCpulsePlugins-Oracle-2.209.7-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"NPalert-1.127.12-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ProgAGoGo-1.11.6-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"PyYAML-3.10-3.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"PyYAML-3.10-3.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"SNMPAlerts-0.5.7-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"SatConfig-bootstrap-1.11.5-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"SatConfig-bootstrap-server-1.13.5-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"SatConfig-cluster-2.2.2-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"SatConfig-general-1.216.31-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"SatConfig-generator-2.29.14-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"SatConfig-installer-3.24.6-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"SatConfig-spread-1.1.3-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"SputLite-client-1.10.1-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"SputLite-server-1.10.1-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ace-editor-1.1.3-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"antlr-2.7.7-7.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"apache-commons-beanutils-1.8.3-10.redhat_2.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"apache-commons-cli-1.2-7.5.redhat_2.ep6.el6.4")) flag++;
  if (rpm_check(release:"RHEL6", reference:"bootstrap-3.0.0-4.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"bootstrap-datepicker-1.3.0-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"c3p0-0.9.1.2-2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"cglib-2.2-5.6.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"cobbler-2.0.7-52.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"cobbler-loaders-1.0.3-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"concurrent-1.3.4-10.1.5_jboss_update1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"cx_Oracle-5.1.2-5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"cx_Oracle-5.1.2-5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"dojo-1.6.1-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"dom4j-1.6.1-11.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"dwr-3.0rc2-6.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"editarea-0.8.2-14.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eventReceivers-2.20.18-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"font-awesome-4.0.3-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"glassfish-jsf-1.2_13-3.1.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate3-3.3.2-1.3.GA_CP04.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"jabberd-2.2.8-23.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jabberd-2.2.8-23.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jabberpy-0.5-0.22.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jakarta-commons-chain-1.2-2.2.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"jakarta-commons-codec-1.3-11.7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jakarta-commons-digester-1.8.1-8.1.1.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jakarta-commons-el-1.0-19.2.1.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jakarta-commons-fileupload-1.1.1-7.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jakarta-commons-io-1.4-4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jakarta-commons-lang-2.4-1.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jakarta-commons-logging-1.1.1-1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jakarta-commons-logging-jboss-1.1-10.3_patch_02.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jakarta-commons-parent-11-2.1.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jakarta-commons-validator-1.3.1-7.5.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"jakarta-oro-2.0.8-6.6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jakarta-taglibs-standard-1.1.1-12.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.6.0-ibm-1.6.0.16.2-1jpp.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-ibm-1.6.0.16.2-1jpp.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.6.0-ibm-devel-1.6.0.16.2-1jpp.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-ibm-devel-1.6.0.16.2-1jpp.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"javassist-3.12.0-6.SP1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-javaee-poms-5.0.1-2.9.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-transaction-1.0.1-api-5.0.1-2.9.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jcommon-1.0.16-1.2.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jdom-1.1.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jfreechart-1.0.13-2.3.2.1.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"jpam-0.4-27.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jpam-0.4-27.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jquery-timepicker-1.3.3-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jquery-ui-1.10.4.custom-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libapreq2-2.13-5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libapreq2-2.13-5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libgsasl-1.4.0-5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libgsasl-1.4.0-5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libntlm-1.0-4.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libntlm-1.0-4.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreadline-java-0.8.0-24.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreadline-java-0.8.0-24.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libyaml-0.1.2-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libyaml-0.1.2-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"momentjs-2.6.0-2.2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"nocpulse-common-2.2.9-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"nocpulse-db-perl-3.6.5-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"nutch-1.0-0.16.20081201040121nightly.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"objectweb-asm-3.2-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"oracle-config-1.1-7.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"oracle-instantclient-basic-10.2.0-47.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"oracle-instantclient-basic-10.2.0-47.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"oracle-instantclient-selinux-10.2.0.19-6.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"oracle-instantclient-sqlplus-10.2.0-47.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"oracle-instantclient-sqlplus-10.2.0-47.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"oracle-instantclient-sqlplus-selinux-10.2.0.19-6.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"oracle-nofcontext-selinux-0.1.23.36-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"osa-dispatcher-5.11.44-5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"osa-dispatcher-selinux-5.11.44-5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"oscache-2.2-3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"patternfly1-1.0.5-4.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-Apache-DBI-1.09-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perl-BerkeleyDB-0.38-6.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perl-BerkeleyDB-0.38-6.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-Cache-Cache-1.06-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perl-Class-MethodMaker-2.16-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-Class-Singleton-1.4-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-Config-IniFiles-2.47-5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-Convert-BinHex-1.119-10.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perl-Crypt-DES-2.05-10.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perl-Crypt-DES-2.05-10.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-Crypt-GeneratePassword-0.03-15.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perl-DBD-Oracle-1.62-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perl-DBD-Oracle-1.62-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perl-DateTime-0.5300-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-Email-Date-Format-1.002-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perl-Filesys-Df-0.92-8.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perl-Filesys-Df-0.92-8.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-HTML-TableExtract-2.10-8.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-IO-stringy-2.110-10.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perl-IPC-ShareLite-0.13-6.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perl-IPC-ShareLite-0.13-6.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perl-List-MoreUtils-0.22-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-MIME-Lite-3.027-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-MIME-Types-1.28-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-MIME-tools-5.427-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-Mail-RFC822-Address-0.3-12.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-NOCpulse-CLAC-1.9.9-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-NOCpulse-Debug-1.23.17-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-NOCpulse-Gritch-2.2.1-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-NOCpulse-Object-1.26.12-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-NOCpulse-OracleDB-1.28.27-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-NOCpulse-PersistentConnection-1.10.1-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-NOCpulse-Probe-1.184.18-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-NOCpulse-Probe-Oracle-1.184.18-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-NOCpulse-ProcessPool-1.6.1-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-NOCpulse-Scheduler-1.58.12-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-NOCpulse-SetID-1.7.2-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-NOCpulse-Utils-1.14.12-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-Net-INET6Glue-0.5-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-Net-IPv4Addr-0.10-7.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-Net-SNMP-6.0.1-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perl-Params-Validate-0.92-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-SOAP-Lite-0.710.10-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-Satcon-1.20-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perl-TermReadKey-2.30-13.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"perl-XML-Generator-1.01-6.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perl-libapreq2-2.13-5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perl-libapreq2-2.13-5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql92-postgresql-9.2.8-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql92-postgresql-9.2.8-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql92-postgresql-contrib-9.2.8-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql92-postgresql-contrib-9.2.8-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql92-postgresql-libs-9.2.8-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql92-postgresql-libs-9.2.8-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql92-postgresql-pltcl-9.2.8-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql92-postgresql-pltcl-9.2.8-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql92-postgresql-server-9.2.8-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql92-postgresql-server-9.2.8-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql92-postgresql-upgrade-9.2.8-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql92-postgresql-upgrade-9.2.8-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql92-runtime-1.1-21.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql92-runtime-1.1-21.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pwstrength-bootstrap-1.0.2-4.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-debian-0.1.16-5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-gzipstream-1.10.2-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-psycopg2-2.0.14-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-psycopg2-2.0.14-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"quartz-1.8.4-5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"quartz-oracle-1.8.4-5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"redstone-xmlrpc-1.1_20071120-15.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhn-i18n-guides-5.7.0.1-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhn-i18n-release-notes-5.7.0.0-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhn-solaris-bootstrap-5.4.1-9.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhn_solaris_bootstrap_5_4_1_9-1-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhnlib-2.5.22-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhnpush-5.5.81-8.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"roboto-1.2-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"satellite-branding-5.7.0.24-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"satellite-doc-indexes-5.7.0-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"satellite-repo-5.6.0.3-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"satellite-schema-5.7.0.11-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"scdb-1.15.8-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"scl-utils-20120927-11.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"scl-utils-20120927-11.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", reference:"select2-3.4.5-3.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"select2-bootstrap-css-1.3.0-5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"simple-core-3.1.3-6.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"sitemesh-2.4.2-2.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacecmd-2.3.0-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-admin-2.2.7-1.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-2.3.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-2.3.3-23.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-app-2.3.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-app-2.3.3-23.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-applet-2.3.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-applet-2.3.3-23.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-config-files-2.3.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-config-files-2.3.3-23.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-config-files-common-2.3.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-config-files-common-2.3.3-23.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-config-files-tool-2.3.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-config-files-tool-2.3.3-23.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-iss-2.3.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-iss-2.3.3-23.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-iss-export-2.3.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-iss-export-2.3.3-23.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-libs-2.3.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-libs-2.3.3-23.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-package-push-server-2.3.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-package-push-server-2.3.3-23.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-server-2.3.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-server-2.3.3-23.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-sql-2.3.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-sql-2.3.3-23.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-sql-oracle-2.3.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-sql-oracle-2.3.3-23.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-sql-postgresql-2.3.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-sql-postgresql-2.3.3-23.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-tools-2.3.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-tools-2.3.3-23.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-xml-export-libs-2.3.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-xml-export-libs-2.3.3-23.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-xmlrpc-2.3.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-xmlrpc-2.3.3-23.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-base-2.3.2-27.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-base-minimal-2.3.2-27.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-base-minimal-config-2.3.2-27.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-certs-tools-2.3.0-4.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-common-2.3.0-1.5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-config-2.3.0-4.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-dobby-2.3.2-27.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-grail-2.3.2-27.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-html-2.3.2-27.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-2.3.8-96.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-config-2.3.8-96.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-lib-2.3.8-96.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-oracle-2.3.8-96.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-postgresql-2.3.8-96.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-monitoring-2.2.1-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-monitoring-selinux-2.2.1-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-oracle-2.3.0-1.5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-postgresql-2.3.0-1.5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-pxt-2.3.2-27.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-reports-2.3.0-5.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-schema-2.3.2-16.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-search-2.3.0-7.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-selinux-2.2.1-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-setup-2.3.0-15.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-setup-jabberd-2.0.1-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-setup-postgresql-2.3.0-21.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-slf4j-1.6.1-6.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-sniglets-2.3.2-27.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-ssl-cert-check-2.3-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-taskomatic-2.3.8-96.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-utils-2.3.2-13.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ssl_bridge-1.9.3-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"status_log_acceptor-0.12.11-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"stringtree-json-2.0.9-10.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"struts-1.3.10-6.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"struts-core-1.3.10-6.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"struts-extras-1.3.10-6.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"struts-taglib-1.3.10-6.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"tanukiwrapper-3.2.3-14.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"tanukiwrapper-3.2.3-14.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tsdb-1.27.29-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"udns-0.1-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"udns-0.1-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"xalan-j2-2.7.0-9.8.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MessageQueue / NOCpulsePlugins / NOCpulsePlugins-Oracle / NPalert / etc");
  }
}
