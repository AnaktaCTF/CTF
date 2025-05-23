# Отказ в обслуживании (Denial of Service SC10:2025) в смарт-контрактах

## Введение

Смарт-контракты – это самовыполняющиеся программы, предназначенные для автоматического исполнения соглашений без участия посредников. Однако их неизменяемость делает уязвимости безопасности особенно сложными для исправления. Одной из потенциальных угроз является атака типа "отказ в обслуживании" (DoS), которая направлена на эксплуатацию логики контракта с целью нарушения работы протокола или блокировки его функциональности для пользователей. Такие атаки могут привести к финансовым потерям и дестабилизации работы смарт-контракта.

В традиционной сетевой безопасности DoS-атака заключается в перегрузке системы или сетевого ресурса чрезмерным количеством запросов, что делает его недоступным для обычных пользователей. Аналогично, злоумышленник может искусственно загружать функции смарт-контракта, чтобы блокировать доступ для других пользователей.

Простая аналогия: представьте себе группу хулиганов, постоянно звонящих в пиццерию, чтобы делать ложные заказы. В результате телефонная линия занята, и настоящие клиенты не могут оформить заказ. Аналогичным образом работают DoS-атаки на смарт-контракты.


## DoS-атаки в Web3
![articles-denial-of-service](https://github.com/user-attachments/assets/7696764d-b2b9-445d-b0ae-7cc437dee553)

В сфере Web3 атака типа "отказ в обслуживании" может заблокировать выполнение отдельных функций или целого смарт-контракта. Это может привести к тому, что пользователи потеряют доступ к контракту либо временно, либо навсегда.

### Пример атаки на децентрализованную биржу (DEX)

Допустим, в децентрализованной бирже (DEX) существует функция `placeOrder`, которая позволяет размещать только 10 ордеров одновременно для всей биржи. Злоумышленник может воспользоваться этим, размещая по 10 ордеров с минимальными суммами (например, по 0.10$), что сделает невозможным выполнение ордеров другими пользователями.

## Основные типы DoS-атак в смарт-контрактах

DoS-атаки могут проявляться разными способами, а их устранение зачастую не является тривиальной задачей. Чаще всего возможности для DoS-атак создаются из-за:

- Логических ошибок в структуре контракта;
- Неправильных предположений о состоянии контракта в момент выполнения операций;
- Особых граничных случаев, которые разработчики могли упустить.

Рассмотрим конкретные примеры.

### Пример DoS из OWASP TOP10

**Пример (Уязвимый контракт):**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Solidity_DOS {
    address public king;
    uint256 public balance;

    function claimThrone() external payable {
        require(msg.value > balance, "Need to pay more to become the king");

        //If the current king has a malicious fallback function that reverts, it will prevent the new king from claiming the throne, causing a Denial of Service.
        (bool sent,) = king.call{value: balance}("");
        require(sent, "Failed to send Ether");

        balance = msg.value;
        king = msg.sender;
    }
}
```

**Воздействие**

-Успешная атака типа «отказ в обслуживании» (DoS) может сделать смарт-контракт неработоспособным, не позволяя пользователям взаимодействовать с ним должным образом. Это может нарушить работу критически важных операций и сервисов, зависящих от данного контракта.

-Атаки DoS могут привести к финансовым потерям, особенно в децентрализованных приложениях (dApps), где смарт-контракты управляют средствами или активами.

-DoS-атака может подорвать репутацию смарт-контракта и связанной с ним платформы. Пользователи могут потерять доверие к безопасности и надёжности платформы, что приведёт к оттоку пользователей и потере бизнес-возможностей.

**Рекомендации по устранению:**

- Используйте функцию call вместо функций send и transfer;

- Ограничьте количество действий, которые могут быть выполнены в рамках одной транзакции;

- Внедрите механизм pull-платежей для возврата или вывода активов, который разделяет процесс начисления и вывода средств на две отдельные транзакции.

**Пример (Исправленный контракт):**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Solidity_DOS {
    address public king;
    uint256 public balance;

    // Use a safer approach to transfer funds, like transfer, which has a fixed gas stipend.
    // This avoids using call and prevents issues with malicious fallback functions.
    function claimThrone() external payable {
        require(msg.value > balance, "Need to pay more to become the king");

        address previousKing = king;
        uint256 previousBalance = balance;

        // Update the state before transferring Ether to prevent reentrancy issues.
        king = msg.sender;
        balance = msg.value;

        // Use transfer instead of call to ensure the transaction doesn't fail due to a malicious fallback.
        payable(previousKing).transfer(previousBalance);
    }
}
```

### DoS через зловредный контракт-получатель

Представим аукционный контракт для продажи редкого предмета. Пользователи отправляют средства в контракт, чтобы сделать ставку. Контракт автоматически отслеживает текущего лидера торгов и возвращает средства предыдущему победителю. В конце аукциона победитель получает предмет.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleAuction {
    address public highestBidder;
    uint public highestBid;

    function bid() public payable {
        require(msg.value > highestBid, "Ставка слишком мала");

        if (highestBidder != address(0)) {
            (bool success, ) = highestBidder.call{value: highestBid}("");
            require(success, "Ошибка при возврате средств");
        }

        highestBidder = msg.sender;
        highestBid = msg.value;
    }
}
```

На первый взгляд этот код кажется исправным, однако злоумышленник может создать вредоносный контракт, который заблокирует возврат средств:

```solidity
pragma solidity ^0.8.0;

contract DOSAuction {
    SimpleAuction public victim;

    constructor(address _auctionAddress) {
        victim = SimpleAuction(_auctionAddress);
    }

    function attack() external payable {
        victim.bid{value: msg.value}();
    }

    receive() external payable {
        revert("Не принимаю возврат!");
    }
}
```

Когда новый пользователь попытается сделать ставку выше, транзакция провалится, так как возврат средств на `DOSAuction` невозможен.

### Как исправить

Один из способов защиты – изменение логики возврата средств, используя паттерн "pull payments":

- Вместо автоматического возврата, сохранять сумму возврата и позволить пользователям самостоятельно её запрашивать.
- Внедрение отдельной функции вывода средств для прошлых участников.

```solidity
mapping(address => uint) pendingReturns;

function withdraw() public {
    uint amount = pendingReturns[msg.sender];
    require(amount > 0, "Нет средств для вывода");

    pendingReturns[msg.sender] = 0;
    payable(msg.sender).transfer(amount);
}
```


## DoS через неограниченные циклы

Циклы без заданного предела могут стать причиной DoS-атак, приводя к исчерпанию газа и блокировке функций контракта. Например:

```solidity
for(i; i< ???; i++) { // Опасно!!! }
while(true) { // Опасно!!! }
```

### Пример: распределение наград

Контракт должен раздать призы победителям, но использует два неэффективных цикла:

```solidity
function distributeRewards(address[] memory winners, uint256[] memory amounts) internal {
    for (uint256 i = 0; i < winners.length; i++) {
        token.transfer(winners[i], amounts[i]);
    }
}
```

Если `winners` содержит слишком много элементов, функция выйдет за пределы лимита газа, и процесс распределения будет невозможен.

### Решение

- Оптимизировать циклы, объединяя вычисления;
- Использовать pull-подход, позволяя победителям самим запрашивать награды;
- Ограничить максимальное количество пользователей в транзакции.


## Заключение

Атаки типа "отказ в обслуживании" представляют серьёзную угрозу для смарт-контрактов и блокчейн-протоколов. Они могут сделать контракт недоступным, нарушить ключевые операции и привести к финансовым потерям. 

Для защиты следует:
- Проверять код на логические уязвимости;
- Избегать автоматического возврата средств;
- Оптимизировать циклы и распределение газа;
- Регулярно проводить аудит кода и тестирование на устойчивость к DoS-атакам.

Разработчики должны учитывать все возможные сценарии атак и проектировать смарт-контракты с устойчивостью к DoS, чтобы гарантировать их безопасность и стабильность в долгосрочной перспективе.



В контексте смарт-контрактов такие атаки происходят, когда злоумышленник вызывает сбой в работе контракта и таким образом делает невозможным его нормальное использование. Также отказ в обслуживании в смарт-контрактах может происходить из-за ошибок в исходном коде или недостатков в логике работы контракта. Злоумышленник может этим воспользоваться, нарушить штатное функционирование контракта и нанести репутационный или финансовый ущерб.

Если в смарт-контракте есть функции, требующие больших вычислительных мощностей (например, циклы для подсчета количества ваших лайков в телеграм-канале, злоумышленник может вызвать их, чтобы израсходовать весь газ и заблокировать контракт.

## Ресурсы

1. Owasp Top 10 Smart-Contracts Vulnerabilitys: https://owasp.org/www-project-smart-contract-top-10/
2.Common Vulnerabilities in Solidity: Denial of Service (DOS): https://www.slowmist.com/articles/solidity-security/Common-Vulnerabilities-in-Solidity-Denial-of-Service-DOS.html
3. Denial of Service (DoS) Attacks in Smart Contracts:  https://www.nethermind.io/blog/denial-of-service-dos-attacks-in-smart-contracts
4. Solidity Smart Contract Unbounded Loops DOS Attack Vulnerability Explained with REAL Example: https://medium.com/@JohnnyTime/solidity-smart-contract-unbounded-loops-dos-attack-vulnerability-explained-with-real-example-f4b4aca27c08
