#%NASL_MIN_LEVEL 5200
##
# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# xml_sax_parser.inc
# $Revision: 1.6 $
#
# This include file handles sax style parsing of simple xml data 
# using a buffer_stream input
#
# @include buffer_stream.inc - nsbs_streamInit(), nsbs_streamRead() xml data stream
##


global_var SAX_CHAR_TABLE,SAXTYPE_XML_DECLARATION,SAXTYPE_STARTING_TAG,
SAXTYPE_TAG_START,SAXTYPE_CLOSING_TAG,SAXTYPE_COMMENT,SAXTYPE_DECLARATION,
SAXTYPE_START_PROCESS_INSTRUCTION,SAXTYPE_END_PROCESS_INSTRUCTION,SAXTYPE_CHARDATA,
IN_STR_Q, IN_STR_A, IN_CON, IN_TAG, IN_CLOSING, SAX_LAST_ERROR, SAX_HTTP_SET_CALLBACK;

SAX_LAST_ERROR = "";

SAXTYPE_XML_DECLARATION           = 0; # <?xml xmlns="xml" ?>
SAXTYPE_STARTING_TAG              = 1; # <tag attr="value>
SAXTYPE_TAG_START                 = 2; # <
SAXTYPE_CLOSING_TAG               = 3; # </close>
SAXTYPE_COMMENT                   = 4; # <!--comment-->
SAXTYPE_DECLARATION               = 5; # <!DOCTYPE foo ...
SAXTYPE_START_PROCESS_INSTRUCTION = 6; # <?word document...
SAXTYPE_END_PROCESS_INSTRUCTION   = 7; # document="test" ?>
SAXTYPE_CHARDATA                  = 8; # stuff

SAX_CHAR_TABLE = make_array(
  "quot", '"',
  "amp", '&',
  "apos", "'",
  "lt", '<',
  "gt", '>'
);

##
# SAX parser
# 
# @param [id:string] the buffer_stream id
# @param [SAX_XMLCALLBACK:function] function pointer to parsing function
# @param [exit_on_fail:bool] exit flag
#
# @return 0 on success, NULL on fail if exit_on_fail is false
##
function SAX_ParseXML(id, SAX_XMLCALLBACK, exit_on_fail)
{
  local_var index, attributesAndValue, currentClosing,
    stBin, currentContent, currentTag, xmlLen, tagStack,
    attribute, buffer, name_space, nmBuffer, currentComment,
    currentEncodedChar, xmlDeclaration, xmlBuf, windowOpen, 
    xml, ENCODED_CHARACTER, ATTR_SET, IN_TAG_NAME, IN_COMMENT,
    windowSize, dchar, IN_CDATA;

  index = 0;

  if (isnull(id))
  {
    SAX_XMLParseError(
      error:"NULL id supplied for SAX_ParseXML",
      xml:"",
      index:0,
      exit_on_fail:exit_on_fail
    );
    return NULL;
  }

  if (typeof(SAX_XMLCALLBACK) != "function")
  {
    SAX_XMLParseError(
      error:"Invalid callback type supplied for SAX_ParseXML",
      xml:"",
      index:0,
      exit_on_fail:exit_on_fail
    );
    return NULL;
  }


  xml = "";
  while (strlen(xml) < 15)
  {
    xmlBuf = nsbs_streamRead(id:id);
    if (isnull(xmlBuf))
    {
      SAX_XMLParseError(
        error:"Stream closed before minimal streaming window could be filled.",
        xml:xml,
        index:0,
        exit_on_fail:exit_on_fail
      );
      return NULL;
    }

    xml += xmlBuf;
  }

  xmlLen = strlen(xml);

  windowOpen = TRUE;
  windowSize = 15;

  # state variables
  stBin = make_array(
    "inStrQ", FALSE,
    "inStrA", FALSE,
    "inCon", FALSE,
    "inTag", FALSE,
    "inClosing", FALSE,
    "inComment", FALSE,
    "inTagName", FALSE,
    "encodedCharacter", FALSE,
    "attributeSet", FALSE,
    "inCDATA", FALSE
  );
  IN_STR_Q = "inStrQ";
  IN_STR_A = "inStrA";
  IN_CON   = "inCon";
  IN_TAG   = "inTag";
  IN_CLOSING = "inClosing";
  ENCODED_CHARACTER = "encodedCharacter";
  ATTR_SET = "attributeSet";
  IN_COMMENT = "inComment";
  IN_TAG_NAME = "inTagName";
  IN_CDATA = "inCDATA";

  # Containers
  currentTag = ""; #store current tag
  attributesAndValue = make_array(); #store current tags attributes;
  currentContent = ""; #current content from the tag we are in;
  currentClosing = ""; #hold the current closing tag value
  currentComment = ""; #holds the content of a comment
  tagStack = make_list(); # keeps track of the location in the xml
  tagStack[0] = 0;

  # Temp Containers for attributes and values
  buffer = "";
  attribute = "";

  # xml declaration
  # http://www.nessus.org/u?a70408ed
  if (substr(xml,0,5) != "<?xml ")
  {
    SAX_XMLParseError(
      error:"XML did not start with a proper open Tag '<?xml'",
      xml:xml,
      index:index,
      exit_on_fail:exit_on_fail);
    return NULL;
  }
  xmlDeclaration = FALSE;

  # Start parsing -------------------------------------------------------  #
  stBin[IN_TAG] = TRUE;
  for (index = 6; index < xmlLen; index++)
  {
    #keep the xml window more than 10 bytes ahead
    if (xmlLen-index < windowSize && windowOpen)
    {
      xmlBuf = nsbs_streamRead(id:id);
      if (isnull(xmlBuf))
        windowOpen = FALSE;

      xml += xmlBuf;
      xml = substr(xml, index);
      xmlLen = strlen(xml);
      index = 0;
    }

    if (stBin[IN_CDATA])
    {
      if (substr(xml, index, index+2) == "]]>")
      {
        stBin[IN_CDATA] = FALSE;
        index += 2;
      }
      else
      {
        currentContent += xml[index]; #add value
      }
      continue;
    }

    if (stBin[IN_TAG])
    {
      #gather the tag name to the currentTag variable
      if (stBin[IN_TAG_NAME])
      {
        if (tolower(xml[index]) >< "abcdefghijklmnopqrstuvwxyz:_")
        {
          currentTag += xml[index];
          continue;
        }
        else if (tolower(xml[index]) >< "0123456789:-." && currentTag != "")
        {
          currentTag += xml[index];
          continue;
        }
        else if (tolower(xml[index]) >< '\n\r')
        {
          continue;
        }
        else if (tolower(xml[index]) >< ' \t')
        {
          if (currentTag == "")
          {
            SAX_XMLParseError(
              error:"invalid ' '(space) in tag name.",
              xml:xml,
              index:index,
              exit_on_fail:exit_on_fail);
            return NULL;
          }
        
          nmBuffer = SAX_XMLGetNamespace(currentTag:currentTag, exit_on_fail:exit_on_fail);
          if (nmBuffer == -1) return NULL;
          if (!isnull(nmBuffer)) name_space = nmBuffer;
          tagStack[tagStack[0]] = currentTag;
          tagStack[0]++;
          stBin[IN_TAG_NAME] = FALSE;
          
          continue;
        }
        else if (xml[index] == ">" || xml[index] == "/")
        {
          nmBuffer = SAX_XMLGetNamespace(currentTag:currentTag, exit_on_fail:exit_on_fail);
          if (nmBuffer == -1) return NULL;
          if (!isnull(nmBuffer)) name_space = nmBuffer;
          tagStack[tagStack[0]] = currentTag;
          tagStack[0]++;
          stBin[IN_TAG_NAME] = FALSE;
          
          index--;
          continue;
        }
        else
        {
          SAX_XMLParseError(
            error:"invalid character in tag '" + xml[index] + "'",
            xml:xml,
            index:index,
            exit_on_fail:exit_on_fail);
          return NULL;
        }
      }
      
      if (xml[index] == ">" && (!stBin[IN_STR_A] && !stBin[IN_STR_Q] && buffer == "" && attribute == ""))
      {
        SAX_XMLCALLBACK(
          currentTag:currentTag,
          attributesAndValue:attributesAndValue,
          currentContent:currentContent,
          currentClosing:currentClosing,
          tagStack:tagStack,
          currentComment:currentComment,
          name_space:name_space,
          type:SAXTYPE_STARTING_TAG
        );

        attributesAndValue = make_array();

        #end Tag start Content
        stBin[IN_TAG] = FALSE;
        stBin[IN_CON] = TRUE;
        continue;
      }
      else if (xml[index] == "'" && !stBin[IN_STR_Q])
      {
        if (attribute == "")
        {
          SAX_XMLParseError(
            error:"opening a string with ' without an associated attribute",
            xml:xml,
            index:index,
            exit_on_fail:exit_on_fail);
          return NULL;
        }
        if (stBin[ENCODED_CHARACTER])
        {
          SAX_XMLParseError(
            error:'encoded character detected in an invalid location.',
            xml:xml,
            index:index,
            exit_on_fail:exit_on_fail);
          return NULL;
        }
        if (stBin[IN_STR_A])
        {
          attributesAndValue[attribute] = buffer;
          attribute = "";
          stBin[ATTR_SET] = FALSE;
          buffer = "";
        }
        stBin[IN_STR_A] = !stBin[IN_STR_A];
      }
      else if (xml[index] == '"' && !stBin[IN_STR_A])
      {
        if (attribute == "")
        {
          SAX_XMLParseError(
            error:'opening a string with " without an associated attribute',
            xml:xml,
            index:index,
            exit_on_fail:exit_on_fail);
          return NULL;
        }
        if (stBin[ENCODED_CHARACTER])
        {
          SAX_XMLParseError(
            error:'encoded character detected in an invalid location.',
            xml:xml,
            index:index,
            exit_on_fail:exit_on_fail);
          return NULL;
        }
        if (stBin[IN_STR_Q])
        {
          attributesAndValue[attribute] = buffer;
          attribute = "";
          stBin[ATTR_SET] = FALSE;
          buffer = "";
        }
        stBin[IN_STR_Q] = !stBin[IN_STR_Q];
      }
      else if (stBin[IN_STR_A] || stBin[IN_STR_Q])
      {
        if (stBin[ENCODED_CHARACTER])
        {
          if (tolower(xml[index]) >< "abcdefghijklmnopqrstuvwxyz0123456789#")
          {
            currentEncodedChar += xml[index];
          }
          else if (xml[index] == ";")
          {
            dchar = SAX_XMLDecodeCharacter(value:currentEncodedChar, exit_on_fail:exit_on_fail);
            if ( isnull(dchar) ) return NULL;
            buffer += dchar;
            currentEncodedChar = "";
            stBin[ENCODED_CHARACTER] = FALSE;
            continue;
          }
          else
          {
            SAX_XMLParseError(
            error:"invalid character '" + xml[index] + "' in encoded character",
            xml:xml,
            index:index,
            exit_on_fail:exit_on_fail);
            return NULL;
          }
          continue;
        }
        
        # validate no illegal chars <
        if (xml[index] == "<")
        {
          SAX_XMLParseError(
            error:"illegal character in string '<'. ",
            xml:xml,
            index:index,
            exit_on_fail:exit_on_fail);
          return NULL;
        }
        else if (xml[index] == "&")
        {
          # '&' signify the start of markup for encoded characters
          currentEncodedChar = "";
          stBin[ENCODED_CHARACTER] = TRUE;
          continue;
        }
        else
        {
          buffer += xml[index];
        }
      }
      else if (xml[index] >< ' \n\r')
      {
        if (attribute != "")
        {
          stBin[ATTR_SET] = TRUE;
        }
        continue;
      }
      else if (xml[index] == "?")
      {
        if (index < xmlLen)
        {
          if (xml[index+1] == ">" && (!stBin[IN_STR_A] && !stBin[IN_STR_Q] && buffer == "" && attribute == ""))
          {
            index++;
          }
          else
          {
            SAX_XMLParseError(
          	error:"invalid location for '?'",
          	xml:xml,
          	index:index,
          	exit_on_fail:exit_on_fail);
            return NULL;
          }
        }
        else
        {
          SAX_XMLParseError(
            error:"invalid location for '?'",
            xml:xml,
            index:index,
            exit_on_fail:exit_on_fail);
          return NULL;
        }
	
        if (!xmlDeclaration)
        {
          SAX_XMLCALLBACK(
            currentTag:currentTag,
            attributesAndValue:attributesAndValue,
            currentContent:currentContent,
            currentClosing:currentClosing,
            tagStack:tagStack,
            currentComment:currentComment,
            name_space:name_space,
            type:SAXTYPE_XML_DECLARATION
          );
          attributesAndValue = make_array();
          tagStack[0]++;
          stBin[IN_TAG] = FALSE;
          xmlDeclaration = TRUE;
        }
        else
        {
          SAX_XMLCALLBACK(
            currentTag:currentTag,
            attributesAndValue:attributesAndValue,
            currentContent:currentContent,
            currentClosing:currentClosing,
            tagStack:tagStack,
            currentComment:currentComment,
            name_space:name_space,
            type:SAXTYPE_END_PROCESS_INSTRUCTION
          );
          tagStack[0]--;
          attributesAndValue = make_array();
          stBin[IN_TAG] = FALSE;
        }
      }
      else if (xml[index] == "/")
      {
        if (index < xmlLen)
        {
          if (xml[index+1] == ">")
          {
            SAX_XMLCALLBACK(
              currentTag:currentTag,
              attributesAndValue:attributesAndValue,
              currentContent:currentContent,
              currentClosing:currentClosing,
              tagStack:tagStack,
              currentComment:currentComment,
              name_space:name_space,
              type:SAXTYPE_STARTING_TAG
              );

            attributesAndValue = make_array();
            currentClosing = currentTag;
            
            tagStack[0]--;
            if (tagStack[0] < 1)
            {
              SAX_XMLParseError(
                error:"irregular tag stack arrangement",
                xml:xml,
                index:index,
                exit_on_fail:exit_on_fail);
              return NULL;
            }

            SAX_XMLCALLBACK(
              currentTag:currentTag,
              attributesAndValue:attributesAndValue,
              currentContent:currentContent,
              currentClosing:currentClosing,
              tagStack:tagStack,
              currentComment:currentComment,
              name_space:name_space,
              type:SAXTYPE_CLOSING_TAG
              );
            currentClosing = "";
            currentTag = tagStack[tagStack[0]-1];
            stBin[IN_TAG] = FALSE;
            stBin[IN_CON] = TRUE;
            index++;
            continue;
          }
        }

        SAX_XMLParseError(
          error:"invalid location for '/'. ",
          xml:xml,
          index:index,
          exit_on_fail:exit_on_fail);
        return NULL;       
      }
      else
      {
        if (stBin[ATTR_SET])
        {
          if (xml[index] == " ") continue;
          if (xml[index] == "=") continue;
          else
          {
            SAX_XMLParseError(
              error:"attribute started when last attribute has not finished.",
              xml:xml,
              index:index,
              exit_on_fail:exit_on_fail);
            return NULL;
          }
        }
        if (tolower(xml[index]) >< "abcdefghijklmnopqrstuvwxyz")
          attribute += xml[index];
        else if (tolower(xml[index]) >< "0123456789:-_" && attribute != "")
          attribute += xml[index];
        else if (xml[index] == "=")
        {
          continue;
        }
        else if (tolower(xml[index]) >< ' \t' && attribute == "")
        {
          continue;
        }
        else
        {
          SAX_XMLParseError(
            error:"invalid character for attribute name '" + xml[index] + "'.",
            xml:xml,
            index:index,
            exit_on_fail:exit_on_fail);
          return NULL;
        }
      }
    }
    else if (!xmlDeclaration)
    {
      SAX_XMLParseError(
        error:"No XML declaration!",
        xml:xml,
        index:0,
        exit_on_fail:exit_on_fail);
      return NULL;
    }
    else if (stBin[IN_CLOSING])
    {
      if (xml[index] == ">")
      {

        tagStack[0]--;
        if (tagStack[tagStack[0]] != currentClosing)
        {
          SAX_XMLParseError(
            error:"Open tag '"+tagStack[tagStack[0]]+"' does not match closing tag '"+currentClosing+"'",
            xml:xml,
            index:index,
            exit_on_fail:exit_on_fail);
          return NULL;
        }

        if (tagStack[0] < 1)
        {
          SAX_XMLParseError(
            error:"Irregular tag stack arrangement",
            xml:xml,
            index:index,
            exit_on_fail:exit_on_fail);
          return NULL ;
        }

        currentTag = tagStack[tagStack[0]-1];
        SAX_XMLCALLBACK(
          currentTag:currentTag,
          attributesAndValue:attributesAndValue,
          currentContent:currentContent,
          currentClosing:currentClosing,
          tagStack:tagStack,
          currentComment:currentComment,
          name_space:name_space,
          type:SAXTYPE_CLOSING_TAG
          );

        stBin[IN_CLOSING] = FALSE;
        stBin[IN_CON] = TRUE;
        currentClosing = "";

        if (tagStack[0] == 1)
        {
          while (windowOpen)
          {
            for (index++;index < xmlLen; index++)
            {
              if (xml[index] == '' || xml[index] == ' ' || xml[index] == '\r' || xml[index] == '\n' )
              {
                continue;
              }
              else
              {
                SAX_XMLParseError(
                  error:"root tag has closed but there is more content in the xml.",
                  xml:xml,
                  index:index,
                  exit_on_fail:exit_on_fail);
                return NULL;
              }
            }
            xml = nsbs_streamRead(id:id);
            if (isnull(xml)) windowOpen = FALSE;
            xmlLen = strlen(xml);
          }
          break;
        }
      }
      else if (tolower(xml[index]) >< "abcdefghijklmnopqrstuvwxyz")
      {
        currentClosing += xml[index];
      }
      else if (tolower(xml[index]) >< "0123456789:-_" && currentClosing != "")
      {
        currentClosing += xml[index];
      }
      else if (xml[index] == " ")
      {
        if (currentClosing == "")
        {
          SAX_XMLParseError(
            error:"invalid space in closing tag",
            xml:xml,
            index:index,
            exit_on_fail:exit_on_fail);
          return NULL;
        }
        
        if (tagStack[tagStack[0]] != currentClosing)
        {
          SAX_XMLParseError(
            error:"Open tag '"+tagStack[tagStack[0]]+"' does not match closing tag '"+currentClosing+"'",
            xml:xml,
            index:index,
            exit_on_fail:exit_on_fail);
          return NULL;
        }

        continue;
      }
      else
      {
        SAX_XMLParseError(
          error:"invalid character in Closing tag '" + xml[index] + "'",
          xml:xml,
          index:index,
          exit_on_fail:exit_on_fail);
        return NULL;
      }
    }
    else  #in content or inbetween tags
    {
      if (stBin[IN_COMMENT])
      {
        if (xml[index] == "-")
        {
          if (substr(xml,index,index+2) == "-->")
          {
          
            SAX_XMLCALLBACK(
               currentTag:currentTag,
               attributesAndValue:attributesAndValue,
               currentContent:currentContent,
               currentClosing:currentClosing,
               tagStack:tagStack,
               currentComment:currentComment,
               name_space:name_space,
               type:SAXTYPE_COMMENT
               );
            
            currentComment = "";
            stBin[IN_COMMENT] = FALSE;
            if(!stBin[IN_TAG])
            {
              stBin[IN_CON] = TRUE;
            }
            index += 2;
            continue;
          }
        }
        currentComment += xml[index];
        continue;
      }
    
      if (stBin[IN_CON])
      {
        #encoded character in content
        if (stBin[ENCODED_CHARACTER])
        {
          if (tolower(xml[index]) >< "abcdefghijklmnopqrstuvwxyz0123456789#")
          {
            currentEncodedChar += xml[index];
          }
          else if (xml[index] == ";")
          {
            dchar = SAX_XMLDecodeCharacter(value:currentEncodedChar, exit_on_fail:exit_on_fail);
            if ( isnull(dchar) ) return NULL;
            currentContent += dchar;
            currentEncodedChar = "";
            stBin[ENCODED_CHARACTER] = FALSE;
            continue;
          }
          else
          {
            SAX_XMLParseError(
            error:"invalid character '" + xml[index] + "' in encoded character",
            xml:xml,
            index:index,
            exit_on_fail:exit_on_fail);
            return NULL;
          }
          continue;
        }
      
        if (xml[index] == "<")
        {
          if (substr(xml, index+1, index+8) == "![CDATA[")
          {
            stBin[IN_CDATA] = TRUE;
            index += 8;
            continue;
          }
          else if(strlen(chomp(currentContent)) > 0)
          {
            SAX_XMLCALLBACK(
              currentTag:currentTag,
              attributesAndValue:attributesAndValue,
              currentContent:currentContent,
              currentClosing:currentClosing,
              tagStack:tagStack,
              currentComment:currentComment,
              name_space:name_space,
              type:SAXTYPE_CHARDATA
            );
          }
        }
        else if (xml[index] == "&")
        {
          # '&' signify the start of markup for encoded characters
          currentEncodedChar = "";
          stBin[ENCODED_CHARACTER] = TRUE;
          continue;
        }
        else
        {
          currentContent += xml[index]; #add value
        }
      } # END IN_CON
      else
      {
        if (xml[index] == " ") continue;
        else if (xml[index] == '\n') continue;
        else if (xml[index] == '\r') continue;
        else if (xml[index] != "<")
        {
          SAX_XMLParseError(
            error:"invalid random character '" + xml[index] + "'",
            xml:xml,
            index:index,
            exit_on_fail:exit_on_fail);
          return NULL;
        }
      }
      

      if (xml[index] == "<")
      {
        if (index < xmlLen)
        {
          if (stBin[IN_CON]) stBin[IN_CON] = !stBin[IN_CON];

          if (xml[index+1] == "/")
          {
            stBin[IN_CLOSING] = TRUE;
            index++;
            currentTag = "";
            currentContent = "";
            continue;
          }

          if (xml[index+1] == "!")
          {
            if (substr(xml,index,index+3) == "<!--")
            { #start of comment
              stBin[IN_COMMENT] = TRUE;
              index+=3;
            }
            else
            { #DTD  #TODO: parse declarations
              
              SAX_XMLCALLBACK(
                currentTag:currentTag,
                attributesAndValue:attributesAndValue,
                currentContent:currentContent,
                currentClosing:currentClosing,
                tagStack:tagStack,
                currentComment:currentComment,
                name_space:name_space,
                type:SAXTYPE_DECLARATION
              );
            }
          }
          else if (xml[index+1] == "?")
          { # TODO expand the parsing of process insctructions
            SAX_XMLCALLBACK(
              currentTag:currentTag,
              attributesAndValue:attributesAndValue,
              currentContent:currentContent,
              currentClosing:currentClosing,
              tagStack:tagStack,
              currentComment:currentComment,
              name_space:name_space,
              type:SAXTYPE_START_PROCESS_INSTRUCTION
              );
            
            currentTag = "";
            stBin[IN_TAG] = TRUE;
            stBin[IN_TAG_NAME] = TRUE;
            index+=1;
          }
          else
          {
            SAX_XMLCALLBACK(
              currentTag:currentTag,
              attributesAndValue:attributesAndValue,
              currentContent:currentContent,
              currentClosing:currentClosing,
              tagStack:tagStack,
              currentComment:currentComment,
              name_space:name_space,
              type:SAXTYPE_TAG_START
            );
 
            currentTag = "";
            currentContent = "";
            stBin[IN_TAG] = TRUE;
            stBin[IN_TAG_NAME] = TRUE;
          }
        }
        else
        {
          SAX_XMLParseError(
            error:"invalid location for '<'",
            xml:xml,
            index:index,
            exit_on_fail:exit_on_fail);
          return NULL;
        }
      }
    }
  }
  if (stBin[IN_CLOSING])
  {
    SAX_XMLParseError(
      error:"Parsing finished while still in closing tag. ",
      xml:xml,
      index:index,
      exit_on_fail:exit_on_fail);
    return NULL;
  }
  if (stBin[IN_TAG])
  {
    SAX_XMLParseError(
      error:"Parsing finished while still in tag. ",
      xml:xml,
      index:index,
      exit_on_fail:exit_on_fail);
    return NULL;
  }
  if (stBin[IN_CON] && tagStack[0] != 1)
  {
    SAX_XMLParseError(
      error:"Parsing finished while still in content. ",
      xml:xml,
      index:index,
      exit_on_fail:exit_on_fail);
    return NULL;
  }
  if (stBin[IN_STR_Q] || stBin[IN_STR_Q])
  {
    SAX_XMLParseError(
      error:"Parsing finished while still in string. ",
      xml:xml,
      index:index,
      exit_on_fail:exit_on_fail);
    return NULL;
  }

  return 0;
}

##
# Parsing Error reporting
#
# @param [error:string] the error message to report
# @param [xml:string] the current xml window
# @param [index:int] the index into the current xml
# @param [exit_on_fail:bool] exit flag
#
# return 0
##
function SAX_XMLParseError(error, xml, index, exit_on_fail)
{
  local_var counter, errorMarker, msg;
  counter = 0;
  errorMarker = "";

  for (; index < strlen(xml); index++)
  {
    counter++;
    errorMarker += xml[index];
    if (counter > 20) break;
  }
  
  msg = error + ' (' + errorMarker + ')';
  if (exit_on_fail) exit(1, msg);
  else
  {
    debug_print(1, msg);
    SAX_LAST_ERROR = msg;
  }

  return 0;
}

##
# returns the last error the sax parser 
# found in the xml
##
function SAX_GetLastError()
{
  return SAX_LAST_ERROR;
}

##
# Decode character entity references
# @Remark &quot;  : double quotation mark
# @Remark &amp;   : ampersand
# @Remark &apos;  : apostrophe (= apostrophe-quote)
# @Remark &lt;    : less-than sign
# @Remark &gt;    : greater-than sign
#
# @param [value:string] encoded character
# @param [exit_on_fail:Bool] exit flag
#
# @return character decoded to ascii, NULL on error
##
function SAX_XMLDecodeCharacter(value, exit_on_fail)
{
  local_var char;

  if (value =~ "^#[0-9]+$")
  {
    char = raw_string(int(substr(value, 1)));    
  }
  else if (value =~ "^#x[0-9a-fA-F]+$")
  {
    char = raw_string(int_hex(substr(value, 2)));
  }
  else
  {
    char = SAX_CHAR_TABLE[value];
    if (isnull(char))
    {
      SAX_XMLParseError(
        error:"invalid character encoding '" + value + "'",
        xml:value,
        index:0,
        exit_on_fail:exit_on_fail
      );
      return NULL;
    }
  }

  return char;
}

##
# Get the namespace
#
# @param [currentTag:string] the current xml tag
# @param [exit_on_fail:bool] exit flag
#
# @return string namespace, NULL if no namespace, -1 on error
##
function SAX_XMLGetNamespace(currentTag, exit_on_fail)
{
  local_var nmBuffer, name_space;

  if (":" >< tolower(currentTag))
  {
    nmBuffer = split(currentTag, sep:":", keep:FALSE);
    if (max_index(nmBuffer) > 2)
    {
      SAX_XMLParseError(
        error:"Tag has too many ':' values in it. ",
        xml:currentTag,
        index:0,
        exit_on_fail:exit_on_fail);
      return -1;
    }
    name_space = nmBuffer[0];
  }
  else name_space = NULL;

  return name_space;
}

function int_hex()
{
  local_var total, i, digit, conv_table, len, hex_str;

  if (isnull(_FCT_ANON_ARGS[0])) return 0;

  hex_str = _FCT_ANON_ARGS[0];
  if (!(hex_str =~ "^[0-9a-fA-F]+$")) return 0;

  conv_table = make_array();
  conv_table["A"] = 10;
  conv_table["B"] = 11;
  conv_table["C"] = 12;
  conv_table["D"] = 13;
  conv_table["E"] = 14;
  conv_table["F"] = 15;

  total = 0;
  len = strlen(hex_str);
  for (i=0; i < len; i++)
  {
    if (toupper(hex_str[i]) >< "0123456789")
    {
      digit = int(hex_str[i]);
    }
    else if(toupper(hex_str[i]) >< "ABCDEF")
    {
      digit = conv_table[hex_str[i]];
    }
    else
    {
      break;
    }
    digit = digit * (16**(len-i-1));
    total += digit;
  }
  return total;
}
