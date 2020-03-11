from al_services.alsvc4_floss.floss import floss


class TestGroupStrings:
    def test_empty_gives_empty(self):
        assert floss.group_strings([]) == []

    def test_single_gives_single(self):
        assert floss.group_strings(['string']) == [['string']]

    def test_duplicates_grouped(self):
        assert floss.group_strings(['string', 'string']) == [['string']]

    def test_like_strings_grouped(self):
        assert floss.group_strings(['string', 'baconator', 'strang', 'baconhater']) == [['string', 'strang'],
                                                                                       ['baconator', 'baconhater']]
