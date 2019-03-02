<#import "/spring.ftl" as spring>
<html>
<h1>Distributor Options</h1>
<ul>
    <#list distributors as distributor>
        <li>
            ${distributor}
        </li>
    </#list>
</ul>
<br>
<a href="logout">Logout</a>
</html>