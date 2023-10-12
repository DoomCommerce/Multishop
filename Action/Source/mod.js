"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const core_1 = require("@actions/core");
const yaml_1 = require("yaml");
const chalk_1 = require("chalk");
try {
    const chalk = new chalk_1.Chalk({ level: 2 });
    console.log(chalk.rgb(200, 100, 50)(`Colored message`));
    class Person {
        constructor(first, last) {
            this.first = first;
            this.last = last;
        }
    }
    const tyrone = new Person("Tyrone", "Jones");
    const janet = new Person("Janet", "Smith");
    const maria = new Person("Maria", "Cruz");
    console.table([tyrone, janet, maria]);
    console.log("Hello via Bun!");
    const yaml = (0, core_1.getInput)('Config');
    console.log('Yaml', yaml);
    const config = (0, yaml_1.parse)(yaml);
    console.log('Config', config);
}
catch (exception) {
    (0, core_1.setFailed)(JSON.stringify(exception, null, 4));
}
