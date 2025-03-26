
<?php

if (!($common instanceof \CommonDBTM)) {
    throw new LogicException();
}

if (!$common::canView()) {
    Html::displayRightError();
}

Html::header(
    $common::getTypeName(2),
    $_SERVER['PHP_SELF'],
    'admin',
    $common::class
);

Search::show($common::class);

Html::footer();
