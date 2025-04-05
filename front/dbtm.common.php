
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
    $place[0] ?? 'admin',
    $place[1] ?? $common::class,
    $place[2] ?? '',
);

Search::show($common::class);

Html::footer();
