<#import "/spring.ftl" as spring>
<html>
<h1>Reseller Options</h1>
<ul>
    <#list resellers as reseller>
        <li>
            ${reseller}
        </li>
    </#list>
</ul>
<br>
<a href="/logout">Logout</a>
</html>