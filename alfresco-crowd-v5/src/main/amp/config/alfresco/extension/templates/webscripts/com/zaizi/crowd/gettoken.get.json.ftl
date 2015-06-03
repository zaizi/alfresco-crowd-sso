<#escape x as jsonUtils.encodeJSONString(x)>
{
   <#if token??>
   "token": "${token}"
   </#if>
}
</#escape>