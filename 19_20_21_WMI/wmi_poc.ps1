$EventFilter = 'SysmonEventFilter'
$EventConsumer = 'SysmonEventConsumer'

$EventFilterParams = @{
    EventNamespace = 'root/cimv2'
    Name = $EventFilter
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 2"
    QueryLanguage = "WQL"
}

$EventConsumerParams = @{
    Name = $EventConsumer
    CommandLineTemplate = "cmd.exe /c powershell.exe Write-Host 'Evil Event Consumer!'"
}

$RegisteredFilter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments $EventFilterParams
$RegisteredConsumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments $EventConsumerParams 

$FilterToConsumerBinding = @{
    Filter = $RegisteredFilter
    Consumer = $RegisteredConsumer
}

$FilterToConsumerBinding = Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments $FilterToConsumerBinding

# Cleanup
$FilterCleanup = Get-WmiObject -Namespace root/subscription -Class __EventFilter -Filter "Name = '$EventFilter'"
$ConsumerCleanup = Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer -Filter "Name = '$EventConsumer'"
$FilterToConsumerBindingCleanup = Get-WmiObject -Namespace root/subscription -Query "REFERENCES OF {$($ConsumerCleanup.__RELPATH)} WHERE ResultClass = __FilterToConsumerBinding"

$FilterCleanup | Remove-WmiObject
$ConsumerCleanup | Remove-WmiObject
$FilterToConsumerBindingCleanup | Remove-WmiObject